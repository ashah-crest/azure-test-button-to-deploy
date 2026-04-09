import configparser
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests


DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "qa.ini")


def t2_hour_utc() -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=2)
    return dt.strftime("%Y%m%d%H")


def generate_hourly_timestamps(start_ts: str, end_ts: Optional[str] = None) -> List[str]:
    end = end_ts.strip() if end_ts else t2_hour_utc()
    try:
        start_dt = datetime.strptime(start_ts.strip(), "%Y%m%d%H").replace(tzinfo=timezone.utc)
        end_dt = datetime.strptime(end, "%Y%m%d%H").replace(tzinfo=timezone.utc)
    except Exception:
        return []

    if start_dt > end_dt:
        return []

    out: List[str] = []
    current = start_dt
    while current <= end_dt:
        out.append(current.strftime("%Y%m%d%H"))
        current += timedelta(hours=1)
    return out


def fetch_and_extract(
    *,
    tl_id: str,
    url: str,
    mode: str,
    api_key: str,
    params: Dict[str, Any],
) -> Tuple[int, Set[Tuple[str, str]], Dict[str, Set[str]]]:
    if mode == "latest":
        print(f"Calling threat_list_id={tl_id} mode=latest", file=sys.stderr)
    else:
        ts = url.rsplit("/", 1)[-1]
        print(f"Calling threat_list_id={tl_id} timestamp={ts}", file=sys.stderr)

    payload = request_json(url, api_key=api_key, params=params)
    objs = iter_iocs(payload)

    all_unique: Set[Tuple[str, str]] = set()
    by_type: Dict[str, Set[str]] = {"ip": set(), "domain": set(), "url": set(), "filehash": set()}
    for obj in objs:
        t = classify_ioc(str(obj.get("type", "")))
        if not t:
            continue
        v = ioc_value(t, obj)
        if not v:
            continue
        v = normalize(t, v)
        if not v:
            continue
        all_unique.add((t, v))
        by_type[t].add(v)

    return len(objs), all_unique, by_type


def read_config(path: str) -> Tuple[str, str, List[str], str, Optional[int], str, Dict[str, str]]:
    parser = configparser.ConfigParser()
    read_ok = parser.read(path)
    if not read_ok:
        return "", DEFAULT_BASE_URL, [], "latest", None, "", {}

    section = "gti"
    api_key = parser.get(section, "api_key", fallback="").strip()
    base_url = parser.get(section, "base_url", fallback=DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
    base_url = base_url.rstrip(".")

    threat_list_ids_raw = parser.get(section, "threat_list_ids", fallback="").strip()
    threat_list_ids = [v.strip() for v in threat_list_ids_raw.split(",") if v.strip()]

    mode = parser.get(section, "mode", fallback="latest").strip().lower() or "latest"
    if mode not in ("latest", "hourly"):
        mode = "latest"

    min_threat_score_raw = parser.get(section, "min_threat_score", fallback="").strip()
    min_threat_score: Optional[int] = None
    if min_threat_score_raw:
        try:
            min_threat_score = int(min_threat_score_raw)
        except Exception:
            min_threat_score = None

    start_timestamp = parser.get(section, "start_timestamp", fallback="").strip()

    per_tl_start_ts: Dict[str, str] = {}
    tl_section = "threat_list_timestamps"
    if tl_section in parser:
        for key, value in parser[tl_section].items():
            k = (key or "").strip()
            v = (value or "").strip()
            if k and v:
                per_tl_start_ts[k] = v

    return api_key, base_url, threat_list_ids, mode, min_threat_score, start_timestamp, per_tl_start_ts


def headers(api_key: str) -> Dict[str, str]:
    return {"accept": "application/json", "x-apikey": api_key}


def request_json(
    url: str,
    *,
    api_key: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resp = requests.get(url, headers=headers(api_key), params=params, timeout=60)
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        detail = ""
        try:
            detail = str(resp.json())
        except Exception:
            detail = resp.text
        raise requests.HTTPError(f"{e} (url={url}) (body={detail})", response=resp) from e
    return resp.json()


def classify_ioc(item_type: str) -> Optional[str]:
    t = (item_type or "").lower()
    if "ip" in t:
        return "ip"
    if "domain" in t:
        return "domain"
    if "url" in t:
        return "url"
    if "file" in t or "hash" in t:
        return "filehash"
    return None


def ioc_value(ioc_type: str, data_obj: Dict[str, Any]) -> Optional[str]:
    if ioc_type == "url":
        return (data_obj.get("attributes") or {}).get("url")
    return data_obj.get("id")


def normalize(ioc_type: str, value: str) -> str:
    v = (value or "").strip()
    if ioc_type == "domain":
        return v.lower()
    return v


def iter_iocs(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    iocs = payload.get("iocs")
    out: List[Dict[str, Any]] = []
    if isinstance(iocs, list):
        for item in iocs:
            if isinstance(item, dict) and isinstance(item.get("data"), dict):
                out.append(item["data"])
            elif isinstance(item, dict):
                out.append(item)
    return out


def main() -> int:
    print(f"Start {datetime.now()}")
    cfg_path = os.environ.get("IOC_COUNTER_CONFIG") or DEFAULT_CONFIG_PATH

    api_key, base_url, threat_list_ids, mode, min_threat_score, start_timestamp, per_tl_start_ts = read_config(cfg_path)

    params: Dict[str, Any] = {"limit": 4000}
    if min_threat_score is not None:
        params["query"] = f"gti_score:{min_threat_score}+"

    all_unique: Set[Tuple[str, str]] = set()
    by_type: Dict[str, Set[str]] = {"ip": set(), "domain": set(), "url": set(), "filehash": set()}
    raw_total = 0

    tasks: List[Tuple[str, str]] = []
    for tl_id in threat_list_ids:
        if mode == "latest":
            tasks.append((tl_id, f"{base_url}/threat_lists/{tl_id}/latest"))
        else:
            start_ts_for_tl = per_tl_start_ts.get(tl_id, start_timestamp)
            timestamps = generate_hourly_timestamps(start_ts_for_tl) if start_ts_for_tl else [t2_hour_utc()]
            for ts in timestamps:
                tasks.append((tl_id, f"{base_url}/threat_lists/{tl_id}/{ts}"))

    max_workers = min(32, (os.cpu_count() or 4) + 4)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                fetch_and_extract,
                tl_id=tl_id,
                url=url,
                mode=mode,
                api_key=api_key,
                params=params,
            )
            for (tl_id, url) in tasks
        ]

        for fut in as_completed(futures):
            try:
                raw_count, uniq, typed = fut.result()
            except Exception as e:
                print(f"Failed fetching: {e}", file=sys.stderr)
                continue

            raw_total += raw_count
            all_unique |= uniq
            for k in by_type:
                by_type[k] |= typed.get(k, set())

    print("Threat lists:", len(threat_list_ids))
    print("Raw IOCs:", raw_total)
    print("Unique IOCs:", len(all_unique))
    print("Unique by type:")
    print("  ip:", len(by_type["ip"]))
    print("  domain:", len(by_type["domain"]))
    print("  url:", len(by_type["url"]))
    print("  filehash:", len(by_type["filehash"]))
    print(f"End {datetime.now()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
