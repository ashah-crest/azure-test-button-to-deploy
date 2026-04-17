# GTI Python SDK

Python client library for the Google Threat Intelligence (GTI) API (VirusTotal).

This repository is intentionally example-heavy. The SDK focuses on a clean,
typed surface area that maps closely to the GTI v3 API while the `examples/`
folder demonstrates real-world usage patterns end-to-end.

This SDK provides:
- Public and private file scanning
- Public and private URL scanning
- IoC enrichment (file, URL, domain, IP)
- Comments API
- IoC Stream and Threat Lists
- DTM (Digital Threat Monitoring) alerts
- ASM (Attack Surface Management) issues

The `examples/` directory contains end-to-end examples for each feature area.

## SDK details

- Synchronous HTTP client built on `requests`
- Consistent exceptions with rich error details (`gti.exceptions`)
- Separate feature modules for scanning, enrichment, feeds, comments, and alerts
- Enum-based options for common parameters (sandboxes, regions, statuses, etc.)

## Folder structure

```text
gti-sdk/
  gti/
    client.py           # Core HTTP client and feature accessors
    constants.py        # Endpoint paths and shared constants
    exceptions.py       # SDK exception hierarchy
    utils.py            # Helper utilities (URL ID encoding)
    features/
      scanning.py       # File/URL scanning (public + private)
      ioc_enrichment.py # File/URL/Domain/IP enrichment
      feeds.py          # IoC Stream + Threat Lists
      comments.py       # Comments API
      alerts.py         # DTM + ASM alerts
  examples/             # Usage examples (primary documentation)
  tests/                # Tests
  pyproject.toml        # Build + dependency config
```

## Requirements

- Python 3.8+
- A GTI API key

## Install

From source (recommended for this repo):

```bash
pip install -e .
```

If published to PyPI under `gti-py`, you can also install with:

```bash
pip install gti-py
```

## Quickstart

```python
from gti import Client

apikey = "your_api_key"

with Client(apikey=apikey) as client:
    # File scan (public)
    result = client.scan_file.scan_and_wait("/path/to/file.exe")
    print(result["stats"])

    # URL scan (public)
    result = client.scan_url.scan_and_wait("https://example.com")
    print(result["stats"])
```

## Authentication

All requests use the `X-Apikey` header.

```python
from gti import Client

client = Client(apikey="your_api_key")
```

By default SSL verification is disabled in the client. For production use,
consider enabling verification:

```python
client = Client(apikey="your_api_key", verify=True)
```

## Features

### File scanning (public)

```python
from gti import Client

with Client(apikey="your_api_key") as client:
    result = client.scan_file.scan_and_wait("/path/to/file.exe")
    print(result["file_info"])
```

### File scanning (private)

```python
from gti import Client
from gti.features.scanning import StorageRegion, FileSandbox

with Client(apikey="your_api_key") as client:
    result = client.scan_file.scan_private_and_wait(
        "/path/to/file.exe",
        storage_region=StorageRegion.EU,
        interaction_sandbox=FileSandbox.CAPE_WIN,
        retention_period_days=7,
    )
    print(result["stats"])
```

### URL scanning (public)

```python
from gti import Client

with Client(apikey="your_api_key") as client:
    result = client.scan_url.scan_and_wait("https://example.com")
    print(result["stats"])
```

### URL scanning (private)

```python
from gti import Client
from gti.features.scanning import StorageRegion, URLSandbox

with Client(apikey="your_api_key") as client:
    result = client.scan_url.scan_private_and_wait(
        "https://internal.example.com",
        storage_region=StorageRegion.US,
        retention_period_days=7,
        sandboxes=[URLSandbox.CHROME_HEADLESS_LINUX],
    )
    print(result.get("gti_assessment", {}))
```

### IoC enrichment

```python
from gti import Client

with Client(apikey="your_api_key") as client:
    file_report = client.file.get("sha256_hash")
    url_report = client.url.get("https://example.com")
    domain_report = client.domain.get("example.com")
    ip_report = client.ip_address.get("8.8.8.8")
```

### IoC Stream

```python
from gti import Client

with Client(apikey="your_api_key") as client:
    recent = client.ioc_stream.get(limit=10)
    for item in client.ioc_stream.iter(filter="entity_type:domain"):
        print(item["id"])
```

### Threat Lists

```python
from gti import Client, ThreatListType, ThreatListFormat

with Client(apikey="your_api_key") as client:
    result = client.threat_list.get_latest(
        ThreatListType.RANSOMWARE,
        limit=100,
        ioc_type="file",
    )

    csv_data = client.threat_list.get_latest(
        ThreatListType.PHISHING,
        format=ThreatListFormat.CSV,
    )
```

### Comments

```python
from gti import Client

with Client(apikey="your_api_key") as client:
    comments = client.comments.get_url_comments("https://example.com", limit=10)
    client.comments.add_domain_comment("example.com", "Known C2 domain")
```

### DTM alerts

```python
from gti import Client, AlertSeverity

with Client(apikey="your_api_key") as client:
    response = client.dtm_alerts.list(severity=[AlertSeverity.HIGH], size=5)
    for alert in response.alerts:
        print(alert["title"])
```

### ASM issues

```python
from gti import Client

with Client(apikey="your_api_key") as client:
    response = client.asm_alerts.search("severity:5", page_size=10)
    hits = response.get("result", {}).get("hits", [])
    for issue in hits:
        print(issue.get("name"))
```

## Examples

The `examples/` directory contains full scripts:
- `examples/scan_file.py`
- `examples/scan_url.py`
- `examples/scan_private_file.py`
- `examples/scan_private_url.py`
- `examples/ioc_stream.py`
- `examples/threat_lists.py`
- `examples/dtm_alerts.py`
- `examples/asm_alerts.py`
