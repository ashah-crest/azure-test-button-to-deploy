"""
GTI Product Profiler — Firecrawl-based feasibility research script
------------------------------------------------------------------
Runs a two-pass web search using Firecrawl's /search endpoint,
scrapes high-value URLs with /scrape, then uses Gemini to extract
a structured product profile aligned with the GTI proposal schema.

Usage:
    python gti_product_profiler.py --product "Hexnode" --vendor "Hexnode UEM"
    python gti_product_profiler.py --product "Splunk SOAR" --vendor "Splunk"
    python gti_product_profiler.py --product "Palo Alto NGFW" --vendor "Palo Alto Networks"

Requirements:
    pip install firecrawl-py google-generativeai python-dotenv

Environment variables (.env):
    FIRECRAWL_API_KEY=fc-...
    GEMINI_API_KEY=AIza...
"""

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from dotenv import load_dotenv
from firecrawl import FirecrawlApp
import google.generativeai as genai

load_dotenv()

# ── Clients ──────────────────────────────────────────────────────────────────

firecrawl = FirecrawlApp(api_key="")

genai.configure(api_key="")
gemini = genai.GenerativeModel(
    model_name="gemini-2.5-flash",
    generation_config=genai.GenerationConfig(
        temperature=0.1,        # low temp for deterministic JSON extraction
        max_output_tokens=2000,
    )
)

# ── Product Profile Schema ────────────────────────────────────────────────────
# Derived from all GTI proposal docs produced in this session:
# GuardDuty, Maltego, TheHive, Splunk SOAR, Proofpoint, Cloudflare,
# Palo Alto NGFW, Atomicorp OSSEC, Hexnode

@dataclass
class SimilarIntegration:
    name: str
    type: str                   # e.g. "threat intelligence", "SOAR", "EDR"
    url: Optional[str] = None

@dataclass
class ProductProfile:
    # ── Core identity
    product_name: str           = ""
    vendor: str                 = ""
    category: str               = ""  # SIEM | SOAR | EDR | MDM | NGFW | TIP | MDM | etc.
    description: str            = ""

    # ── Marketplace & ecosystem
    marketplace_available: Optional[bool]   = None
    marketplace_type: str                   = ""  # public | private | none
    marketplace_url: Optional[str]          = None
    similar_integrations: list              = field(default_factory=list)
    virustotal_integration_exists: Optional[bool] = None
    threat_intel_integrations: list         = field(default_factory=list)

    # ── API & developer surface
    api_available: Optional[bool]           = None
    api_type: str                           = ""  # REST | GraphQL | webhook | file-based | none
    api_docs_url: Optional[str]             = None
    sdk_available: Optional[bool]           = None
    sdk_language: Optional[str]             = None
    auth_method: str                        = ""  # API key | OAuth 2.0 | Basic Auth | none
    third_party_dev_allowed: Optional[bool] = None
    inbound_feed_support: str               = ""  # STIX/TAXII | custom API | file-based | none

    # ── Publishing & partnership
    partnership_required: Optional[str]     = None  # true | false | unknown
    partnership_program_name: Optional[str] = None
    partnership_url: Optional[str]          = None
    self_publish_path: Optional[str]        = None
    inhouse_dev_only: Optional[bool]        = None

    # ── GTI use case fit
    feasible_use_cases: list                = field(default_factory=list)
    unsupported_ioc_types: list             = field(default_factory=list)
    integration_model: str                  = ""  # connector/agent | feed/pull | API push | file-based | config-only
    trigger_model: str                      = ""  # manual/on-demand | scheduled | event-driven | continuous

    # ── Trial & access
    trial_available: Optional[bool]         = None
    trial_type: str                         = ""  # self-serve | sales-assisted | demo only | none
    trial_url: Optional[str]                = None
    trial_limitations: Optional[str]        = None

    # ── Feasibility verdict
    feasibility_status: str                 = ""  # feasible | partially_feasible | not_feasible | pending
    proposal_status: str                    = ""  # in_progress | not_feasible | pending_partnership | blocked
    blockers: list                          = field(default_factory=list)
    key_risks: list                         = field(default_factory=list)

    # ── Source tracking
    sources_used: list                      = field(default_factory=list)

# ── Search query builder ──────────────────────────────────────────────────────

def build_pass1_queries(product: str, vendor: str) -> list[str]:
    """Six core queries — always run."""
    return [
        f"{product} {vendor} security platform overview",
        f"{product} integrations marketplace third party",
        f"{product} VirusTotal threat intelligence integration",
        f"{product} REST API documentation",
        f"{product} SDK Python plugin connector",
        f"{product} partner program ISV technology alliance",
    ]

def build_pass2_queries(product: str, null_fields: list[str]) -> list[str]:
    """Gap-fill queries — only fired for null schema fields."""
    gap_map = {
        "publishing_path":    f"{product} publish integration submit GitHub contribute",
        "inbound_feed":       f"{product} STIX TAXII IOC inbound threat feed ingestion",
        "auth_method":        f"{product} API authentication OAuth API key webhook",
        "trial":              f"{product} free trial sandbox developer account",
        "blockers":           f"{product} API rate limits known issues limitations",
        "partnership":        f"{product} partner program inhouse integration development",
    }
    queries = []
    for field_name in null_fields:
        for key, q in gap_map.items():
            if key in field_name and q not in queries:
                queries.append(q)
    return queries

def detect_null_fields(profile: ProductProfile) -> list[str]:
    """Return field names that are still null, empty, or unknown after pass 1."""
    null = []
    d = asdict(profile)
    check = [
        "api_available", "api_type", "auth_method",
        "marketplace_available", "marketplace_type",
        "partnership_required", "self_publish_path",
        "inbound_feed_support", "trial_available", "trial_type",
        "feasibility_status", "blockers",
    ]
    for f in check:
        v = d.get(f)
        if v is None or v == "" or v == "unknown" or v == []:
            null.append(f)
    return null

# ── Firecrawl helpers ─────────────────────────────────────────────────────────

def search(query: str, limit: int = 5) -> list[dict]:
    """Run a Firecrawl search and return result list."""
    try:
        result = firecrawl.search(
            query=query,
            limit=limit,
        )
        # firecrawl-py returns a SearchResponse with .data list
        items = result.data if hasattr(result, "data") else (result if isinstance(result, list) else [])
        return [
            {
                "url":     getattr(r, "url",         r.get("url",         "")) if not isinstance(r, dict) else r.get("url", ""),
                "title":   getattr(r, "title",       r.get("title",       "")) if not isinstance(r, dict) else r.get("title", ""),
                "content": getattr(r, "markdown",    r.get("markdown", getattr(r, "description", r.get("description", "")))) if not isinstance(r, dict) else r.get("markdown", r.get("description", "")),
            }
            for r in items
        ]
    except Exception as e:
        print(f"  [search error] {query!r}: {e}")
        return []

def scrape(url: str) -> str:
    """Scrape a single URL and return clean markdown. Returns '' on failure."""
    try:
        result = firecrawl.scrape_url(
            url,
            formats=["markdown"],
            only_main_content=True,
        )
        # firecrawl-py v1: result is ScrapeResponse with .markdown attribute
        return getattr(result, "markdown", None) or (result.get("markdown", "") if isinstance(result, dict) else "")
    except Exception as e:
        print(f"  [scrape error] {url}: {e}")
        return ""

def candidate_scrape_urls(vendor: str, search_results: list[dict]) -> list[str]:
    """
    Build a list of high-value URLs to scrape directly.
    Combines known vendor URL patterns with any docs/marketplace
    URLs surfaced in search results.
    """
    vendor_slug = vendor.lower().replace(" ", "").replace(".", "")
    # known_patterns = [
    #     f"https://www.{vendor_slug}.com/developers/",
    #     f"https://www.{vendor_slug}.com/integrations/",
    #     f"https://www.{vendor_slug}.com/marketplace/",
    #     f"https://www.{vendor_slug}.com/partners/",
    #     f"https://github.com/{vendor_slug}/",
    #     f"https://docs.{vendor_slug}.com/",
    # ]
    # Pull any URL from search results that looks like docs/marketplace/partners
    keywords = ["developer", "integration", "marketplace", "partner", "api", "docs", "github"]
    result_urls = [
        r["url"] for r in search_results
        if any(k in r["url"].lower() for k in keywords)
        and r["url"].startswith("http")
    ]
    # Deduplicate — result URLs take priority
    seen = set()
    urls = []
    for u in result_urls:
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls[:6]  # cap at 6 scrapes to control cost

# ── Claude extraction ─────────────────────────────────────────────────────────

EXTRACTION_SYSTEM = """
You are a security product research assistant helping assess feasibility of integrating 
Google Threat Intelligence (GTI) with third-party security products.

Given web search results and scraped page content about a security product, extract a 
structured product profile as a JSON object. Use only information present in the provided 
content — do not hallucinate. If a field cannot be determined, use null.

The GTI integration context:
- GTI (Google Threat Intelligence) provides threat intel data: IOC enrichment, threat lists 
  (IPs, domains, URLs, file hashes), threat actor attribution, malware family data, CVE context.
- Common GTI integration patterns: REST API enrichment, STIX/TAXII feed ingestion, 
  custom connector/plugin, file-based EDL/CDB list sync, marketplace app submission.
- The goal is to determine whether and how GTI data can be operationalized in the target product.

Return ONLY valid JSON matching this schema exactly — no prose, no markdown fences:

{
  "product_name": string,
  "vendor": string,
  "category": string,
  "description": string (1-2 sentences),

  "marketplace_available": boolean | null,
  "marketplace_type": "public" | "private" | "none" | null,
  "marketplace_url": string | null,
  "similar_integrations": [{"name": string, "type": string, "url": string | null}],
  "virustotal_integration_exists": boolean | null,
  "threat_intel_integrations": [string],

  "api_available": boolean | null,
  "api_type": "REST" | "GraphQL" | "webhook" | "file-based" | "none" | null,
  "api_docs_url": string | null,
  "sdk_available": boolean | null,
  "sdk_language": string | null,
  "auth_method": "API key" | "OAuth 2.0" | "Basic Auth" | "multiple" | "none" | null,
  "third_party_dev_allowed": boolean | null,
  "inbound_feed_support": "STIX/TAXII" | "custom API" | "file-based" | "none" | null,

  "partnership_required": "true" | "false" | "unknown",
  "partnership_program_name": string | null,
  "partnership_url": string | null,
  "self_publish_path": string | null,
  "inhouse_dev_only": boolean | null,

  "feasible_use_cases": [string],
  "unsupported_ioc_types": [string],
  "integration_model": "connector/agent" | "feed/pull" | "API push" | "file-based" | "config-only" | null,
  "trigger_model": "manual/on-demand" | "scheduled" | "event-driven" | "continuous" | null,

  "trial_available": boolean | null,
  "trial_type": "self-serve" | "sales-assisted" | "demo only" | "none" | null,
  "trial_url": string | null,
  "trial_limitations": string | null,

  "feasibility_status": "feasible" | "partially_feasible" | "not_feasible" | "pending",
  "proposal_status": "in_progress" | "not_feasible" | "pending_partnership" | "blocked",
  "blockers": [string],
  "key_risks": [string]
}
"""

def extract_profile(product: str, vendor: str, content_chunks: list[str]) -> dict:
    """Send all collected content to Gemini for structured extraction."""
    combined = "\n\n---\n\n".join(content_chunks)
    # Gemini 2.0 Flash has a 1M token context — cap at ~200k chars to be safe
    if len(combined) > 200000:
        combined = combined[:200000] + "\n\n[content truncated]"

    prompt = (
        f"{EXTRACTION_SYSTEM}\n\n"
        f"Product: {product}\nVendor: {vendor}\n\n"
        f"Research content:\n\n{combined}"
    )

    response = gemini.generate_content(prompt)
    raw = response.text.strip()

    # Strip markdown fences if Gemini wrapped the JSON
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"  [parse error] Gemini response was not valid JSON: {e}")
        print(f"  Raw: {raw[:500]}")
        return {}

# ── Main pipeline ─────────────────────────────────────────────────────────────

def run(product: str, vendor: str, output_path: Optional[str] = None) -> ProductProfile:
    print(f"\n{'='*60}")
    print(f"  GTI Product Profiler")
    print(f"  Product : {product}")
    print(f"  Vendor  : {vendor}")
    print(f"{'='*60}\n")

    all_content: list[str] = []
    all_sources: list[str] = []
    all_results: list[dict] = []

    # ── Pass 1: core search queries ──────────────────────────────────────────
    print("[ Pass 1 ] Running core search queries...")
    for q in build_pass1_queries(product, vendor):
        print(f"  search: {q!r}")
        results = search(q, limit=4)
        all_results.extend(results)
        for r in results:
            if r["content"]:
                all_content.append(f"# {r['title']}\nURL: {r['url']}\n\n{r['content']}")
            if r["url"] and r["url"] not in all_sources:
                all_sources.append(r["url"])
        time.sleep(0.5)  # gentle rate limiting

    # ── Pass 1.5: scrape high-value URLs ────────────────────────────────────
    print("\n[ Pass 1.5 ] Scraping high-value URLs...")
    scrape_urls = candidate_scrape_urls(vendor, all_results)
    for url in scrape_urls:
        print(f"  scrape: {url}")
        md = scrape(url)
        if md:
            all_content.append(f"# Scraped: {url}\n\n{md[:8000]}")  # cap per page
            if url not in all_sources:
                all_sources.append(url)
        time.sleep(0.5)

    # ── Pass 1 extraction ────────────────────────────────────────────────────
    print("\n[ Extraction ] Sending to Claude for structured extraction (pass 1)...")
    extracted = extract_profile(product, vendor, all_content)

    # Merge into dataclass
    profile = ProductProfile()
    for k, v in extracted.items():
        if hasattr(profile, k):
            setattr(profile, k, v)
    profile.sources_used = all_sources

    # ── Pass 2: gap-fill for null fields ────────────────────────────────────
    null_fields = detect_null_fields(profile)
    if null_fields:
        print(f"\n[ Pass 2 ] Null fields detected: {null_fields}")
        p2_queries = build_pass2_queries(product, null_fields)
        if p2_queries:
            for q in p2_queries:
                print(f"  search: {q!r}")
                results = search(q, limit=3)
                for r in results:
                    if r["content"] and r["content"] not in all_content:
                        all_content.append(f"# {r['title']}\nURL: {r['url']}\n\n{r['content']}")
                    if r["url"] and r["url"] not in all_sources:
                        all_sources.append(r["url"])
                time.sleep(0.5)

            print("\n[ Extraction ] Re-extracting with gap-fill content...")
            extracted2 = extract_profile(product, vendor, all_content)
            # Only update fields that were null
            for k in null_fields:
                if k in extracted2 and extracted2[k] not in (None, "", [], "unknown"):
                    if hasattr(profile, k):
                        setattr(profile, k, extracted2[k])

    profile.sources_used = list(dict.fromkeys(all_sources))  # deduplicate

    # ── Output ───────────────────────────────────────────────────────────────
    result_dict = asdict(profile)

    print("\n[ Result ] Product Profile:")
    print(json.dumps(result_dict, indent=2))

    # Save to file
    if not output_path:
        safe_name = product.lower().replace(" ", "_").replace("/", "_")
        output_path = f"{safe_name}_profile.json"

    with open(output_path, "w") as f:
        json.dump(result_dict, f, indent=2)
    print(f"\n[ Saved ] {output_path}")

    return profile

# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="GTI Product Feasibility Profiler")
    # parser.add_argument("--product", required=True, help="Product name, e.g. 'Hexnode'")
    # parser.add_argument("--vendor",  required=True, help="Vendor name, e.g. 'Hexnode UEM'")
    # parser.add_argument("--output",  help="Output JSON path (default: {product}_profile.json)")
    # args = parser.parse_args()

    run(
        product="Zoho Desk",
        vendor="Zoho Desk",
        # output_path=args.output,
    )