#!/usr/bin/env python3

import os
import json
import logging
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional, Dict

import requests
import configparser

from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from filelock import FileLock  # cross-platform lock

VERSION = "1.0.0"
API_TIMEOUT = 60
MAX_LIMIT = 4000
MAX_WORKERS = 6
IOC_TTL = 60  # TTL in seconds (e.g., 7 days)
MAX_CDB_FILE_SIZE = 50 * 1024 * 1024  # Maximum file size (for warning purposes only, bytes)

THREAT_LIST_IDS = ["ransomware", "malicious-network-infrastructure", "malware", "threat-actor", "trending",
                   "mobile", "osx", "linux", "iot", "cryptominer", "phishing", "first-stage-delivery-vectors",
                   "vulnerability-weaponization", "infostealer"]
SEVERITIES = ["SEVERITY_NONE", "SEVERITY_LOW", "SEVERITY_MEDIUM", "SEVERITY_HIGH", "SEVERITY_UNKNOWN"]
VERDICTS = ["VERDICT_BENIGN", "VERDICT_UNDETECTED", "VERDICT_SUSPICIOUS", "VERDICT_MALICIOUS", "VERDICT_UNKNOWN"]

IOC_TYPE_MAP = {
    "ip_address": "ip",
    "domain": "domain",
    "url": "url",
    "file": "hash"
}

IP_FIELDS = {
    "v": "gti_assessment.verdict.value",
    "s": "gti_assessment.severity.value",
    "ts": "gti_assessment.threat_score.value",
    "lmd": "last_modification_date",
    "c": "country",
    "asn": "asn",
    "as_owner": "as_owner"
}

URL_FIELDS = {
    "v": "gti_assessment.verdict.value",
    "s": "gti_assessment.severity.value",
    "ts": "gti_assessment.threat_score.value",
    "fsd": "first_submission_date",
    "lsd": "last_submission_date",
    "lmd": "last_modification_date",
    "lad": "last_analysis_date"
}

DOMAIN_FIELDS = {
    "v": "gti_assessment.verdict.value",
    "s": "gti_assessment.severity.value",
    "ts": "gti_assessment.threat_score.value",
    "lmd": "last_modification_date",
    "cd": "creation_date",
}

FILE_HASH_FIELDS = {
    "v": "gti_assessment.verdict.value",
    "s": "gti_assessment.severity.value",
    "ts": "gti_assessment.threat_score.value",
    "lmd": "last_modification_date",
    "cd": "creation_date",
    "lsd": "last_submission_date",
    "lad": "last_analysis_date",
    "md5": "md5",
    "sha256": "sha256",
    "meaningful_name": "meaningful_name"
}


# -------------------- helpers --------------------

def ensure_dir(path):
    if path:
        os.makedirs(path, exist_ok=True)


def utc_hour(dt):
    return dt.strftime("%Y%m%d%H")


def latest_hour():
    # GTI latest available = current UTC - 2 hours
    return datetime.utcnow() - timedelta(hours=2)


def construct_info_dict(source_dict: dict, field_mapping: dict) -> dict:
    """
    Extract fields from a nested dictionary using dot notation paths.
    
    Args:
        source_dict: The source dictionary with potentially nested data
        field_mapping: A dictionary mapping output keys to dot-notation paths
        
    Returns:
        A new dictionary with extracted values
    """
    result = {}

    for output_key, path in field_mapping.items():
        # Split the path by dots to traverse nested structure
        keys = path.split('.')
        value = source_dict
        # Traverse the nested dictionary
        try:
            for key in keys:
                value = value[key]
            result[output_key] = value
        except (KeyError, TypeError):
            # If path doesn't exist, skip or set to None
            result[output_key] = None

    return result


# -------------------- config --------------------

@dataclass
class Config:
    api_key: str
    base_url: str
    checkpoint: str
    threat_lists: List[str]
    severities: List[str]
    verdicts: List[str]
    threat_score: Optional[int]
    cdb_dir: str
    output: Dict[str, str]
    log_file: str
    lock_file: str


def load_config(path):
    logging.info("Loading config from %s", path)
    parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    parser.read(path)

    threat_lists = [
        x.strip()
        for x in parser.get("filters", "threat_list_ids").split(",")
    ]
    score = parser.get("filters", "threat_score", fallback=None)

    severity_filter = parser.get("filters", "severities")
    if severity_filter:
        severities = [x.strip() for x in severity_filter.split(",")]
    else:
        severities = SEVERITIES

    verdict_filter = parser.get("filters", "verdicts")
    if verdict_filter:
        verdicts = [x.strip() for x in verdict_filter.split(",")]
    else:
        verdicts = VERDICTS

    return Config(
        api_key=parser.get("gti", "api_key"),
        base_url=parser.get("gti", "base_url"),
        checkpoint=parser.get("gti", "checkpoint_file"),
        threat_lists=threat_lists,
        severities=severities,
        verdicts=verdicts,
        threat_score=int(score) if score else None,
        cdb_dir=parser.get("wazuh", "cdb_dir"),
        output={
            "ip": parser.get("output", "ip_list"),
            "domain": parser.get("output", "domain_list"),
            "url": parser.get("output", "url_list"),
            "hash": parser.get("output", "hash_list"),
        },
        log_file=parser.get("logging", "log_file"),
        lock_file=parser.get("logging", "lock_file"),
    )


# -------------------- logging --------------------

def setup_logging(path):
    # ensure_dir(os.path.dirname(path))
    logging.basicConfig(
        # filename=path,
        level=logging.INFO,
        format="%(asctime)sZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)]
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("GTI_SYNC")


# -------------------- checkpoint --------------------

class Checkpoint:

    def __init__(self, cfg):
        self.path = path = cfg.checkpoint
        ensure_dir(os.path.dirname(path))
        self.data = {}
        if os.path.exists(path):
            logging.info("Loading last checkpoint from %s", path)
            try:
                with open(path) as f:
                    self.data = json.load(f)
            except Exception:
                logging.warning("Checkpoint corrupted resetting")
                self.data = {}
        else:
            logging.info("No checkpoint found creating New")
            for tl in cfg.threat_lists:
                self.data[tl] = None

    def get(self, k):
        return self.data.get(k)

    def update(self, k, v):
        self.data[k] = v

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)


# -------------------- GTI client --------------------

class GTIClient:

    def __init__(self, cfg):
        self.base = cfg.base_url
        self.key = cfg.api_key
        self.score = cfg.threat_score

    def _headers(self):
        return {"accept": "application/json", "x-apikey": self.key}

    def _params(self):
        p = {"limit": MAX_LIMIT}
        if self.score is not None:
            p["query"] = f"gti_score:{self.score}+"
        return p

    def fetch_latest(self, tl):
        url = f"{self.base}/threat_lists/{tl}/latest"
        r = requests.get(url, headers=self._headers(), params=self._params(), timeout=60)
        r.raise_for_status()
        return r.json()

    def fetch_hour(self, tl, hour):
        url = f"{self.base}/threat_lists/{tl}/{hour}"
        r = requests.get(url, headers=self._headers(), params=self._params(), timeout=60)
        r.raise_for_status()
        return r.json()


# -------------------- IOC store --------------------

class IOCStore:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        # ensure output directory exists
        os.makedirs(cfg.cdb_dir, exist_ok=True)

        # initialize data buckets per category
        self.data = {cat: {} for cat in cfg.output.keys()}

        # track if data changed for conditional write
        self.changed = False

        self.now = int(time.time())

        # load existing CDB files into memory
        self._load_existing()

    def _load_existing(self):
        """Load existing CDB files into memory at startup."""
        expired = 0
        for cat, fname in self.cfg.output.items():
            path = os.path.join(self.cfg.cdb_dir, fname)
            if not os.path.exists(path):
                continue
            try:
                logging.info("loading CDB file path=%s", path)
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or ":" not in line:
                            continue
                        key, value = line.split(":", 1)
                        ts_str, payload = value.split("|", 1)
                        ts = int(ts_str)
                        if self.now - ts > IOC_TTL:
                            expired += 1
                            continue  # expired IOCs removed
                        self.data[cat][key] = value
                logging.info("loaded CDB file path=%s expired=%d", path, expired)
            except Exception as e:
                logging.warning(
                    "Failed to load CDB file path=%s error=%s", path, e
                )

    def _serialize(self, ioc: dict, cat: str) -> tuple:
        """
        Convert IOC to minimal payload for CDB storage.
        Returns (ioc_key, payload_string, category)
        """
        data = ioc.get("data", {})
        attr = data.get("attributes", "data")

        key = self._key(ioc)
        fields_list = {}
        match cat:
            case "ip":
                fields_list = IP_FIELDS
            case "url":
                fields_list = URL_FIELDS
            case "domain":
                fields_list = DOMAIN_FIELDS
            case "hash":
                fields_list = FILE_HASH_FIELDS
        payload = construct_info_dict(attr, fields_list)
        # JSON string with minimal formatting
        return key, json.dumps(payload).replace('"', "'")

    def _classify(self, ioc):
        data = ioc.get("data", {})
        return IOC_TYPE_MAP.get(data.get("type"))

    def _key(self, ioc):
        d = ioc.get("data", {})
        if d.get("type") == "url":
            return d.get("attributes", {}).get("url", d.get("id"))
        return d.get("id")

    def merge(self, iocs: list):
        """
        Merge a list of IOCs into store.
        Refreshes ingestion timestamp if key already exists.
        Returns (added_count, updated_count)
        """
        added = updated = skipped = 0
        for ioc in iocs:
            cat = self._classify(ioc)
            if not cat:
                continue
            key, payload = self._serialize(ioc, cat)
            if not key:
                skipped += 1
                continue
            line = f"{self.now}|{payload}"
            bucket = self.data[cat]
            if key in bucket:
                bucket[key] = line
                updated += 1
            else:
                bucket[key] = line
                added += 1
        if added or updated:
            self.changed = True
        return added, updated, skipped

    def write(self):
        """
        Write CDB lists to disk atomically.
        Removes expired IOCs based on TTL.
        Warns if file exceeds MAX_CDB_FILE_SIZE but preserves valid IOCs.
        """
        if not self.changed:
            return

        for cat, fname in self.cfg.output.items():
            path = os.path.join(self.cfg.cdb_dir, fname)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
            total_written = 0
            with os.fdopen(fd, "w") as f:
                for k, line in self.data[cat].items():
                    f.write(f"{k}:{line}\n")
                    total_written += 1
            os.replace(tmp, path)
            file_size = os.path.getsize(path)
            if file_size > MAX_CDB_FILE_SIZE:
                logging.warning(
                    "file_size_exceeded category=%s size=%d bytes. Valid IOCs preserved.",
                    cat,
                    file_size
                )
            logging.info(
                "cdb_write category=%s written=%d final_size=%d bytes",
                cat,
                total_written,
                file_size
            )
        self.changed = False
        # return file_size_flag


# -------------------- fetch tasks --------------------

def build_tasks(cfg, checkpoint):
    tasks = []
    target = latest_hour()
    for tl in cfg.threat_lists:
        last = checkpoint.get(tl)
        if not last:
            tasks.append(("latest", tl, None))
            continue
        start = datetime.strptime(last, "%Y%m%d%H") + timedelta(hours=1)
        while start <= target:
            tasks.append(("hour", tl, utc_hour(start)))
            start += timedelta(hours=1)
    return tasks


def fetch_parallel(client, tasks):
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_map = {}
        for task in tasks:
            mode, tl, hour = task
            if mode == "latest":
                future = pool.submit(client.fetch_latest, tl)
            else:
                future = pool.submit(client.fetch_hour, tl, hour)
            future_map[future] = task

        for future in as_completed(future_map):
            task = future_map[future]
            try:
                result = future.result()
                results.append((task, result))
            except Exception as e:
                logging.error("fetch failed task=%s error=%s", task, e)
    return results


def extract_iocs(resp):
    if not resp:
        return []
    return resp.get("iocs") or resp.get("data") or []


def filter_iocs(iocs):
    for ioc in iocs:
        print(json.dumps(ioc))


def process_response(task, response, store, checkpoint, metrics):
    mode, threat_list, hour = task
    try:
        logging.info("Fetching for threat_list=%s hour=%s", threat_list, hour)
        iocs = extract_iocs(response)
        count = len(iocs)
        metrics["total_iocs"] += count
        logging.info("Fetched %d iocs", count)
        added, updated, skipped = store.merge(iocs)
        metrics["added"] += added
        metrics["updated"] += updated
        metrics["skipped"] += skipped
        logging.info(
            "merge threat_list=%s added=%d updated=%d skiipped=%d",
            threat_list,
            added,
            updated,
            skipped
        )

        # update checkpoint safely
        if mode == "latest":
            checkpoint.update(threat_list, utc_hour(latest_hour()))
        elif hour:
            checkpoint.update(threat_list, hour)
    except Exception as e:
        logging.error(
            "processing_failure threat_list=%s hour=%s error=%s",
            threat_list,
            hour,
            e
        )


# -------------------- main --------------------

def main():
    logging.info("Execution for GTI Sync started version=%s", VERSION)
    cfg = load_config("gti_config.ini")
    setup_logging(cfg.log_file)
    lock_path = cfg.lock_file + ".lock"
    try:
        with FileLock(lock_path, timeout=0):
            checkpoint = Checkpoint(cfg)
            client = GTIClient(cfg)
            store = IOCStore(cfg)
            tasks = build_tasks(cfg, checkpoint)
            if not tasks:
                logging.info("Nothing to process, data is up to date")
                return
            logging.info("Number of tasks to process=%d", len(tasks))
            metrics = {
                "total_iocs": 0,
                "added": 0,
                "updated": 0,
                "skipped": 0
            }
            processed_count = 0
            try:
                responses = fetch_parallel(client, tasks)
                for task, response in responses:
                    process_response(
                        task,
                        response,
                        store,
                        checkpoint,
                        metrics
                    )
                    processed_count += 1
                    # periodic persistence (extra safety)
                    if processed_count % 5 == 0:
                        store.write()
                        checkpoint.save()
                        logging.info(
                            "periodic_persist processed=%d",
                            processed_count
                        )
            except Exception as e:
                logging.error("processing_loop_failure error=%s", e)
            finally:
                # fail-safe persistence
                try:
                    store.write()
                    checkpoint.save()
                    logging.info(
                        "run_summary total_iocs=%d added=%d updated=%d skipped=%d",
                        metrics["total_iocs"],
                        metrics["added"],
                        metrics["updated"],
                        metrics["skipped"]
                    )
                except Exception as e:
                    logging.error("final_persist_failed error=%s", e)
            logging.info("GTI ingestion finished")
    except TimeoutError:
        logging.warning("another_instance_running")


if __name__ == "__main__":
    main()
