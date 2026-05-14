"""
GTI Product Profiler
Usage : python gti_product_profiler_v1.py --product "Splunk SOAR"
Deps  : pip install firecrawl-py google-generativeai python-dotenv
.env  : FIRECRAWL_API_KEY=fc-...   GEMINI_API_KEY=AIza...
"""

import os, json, argparse, time
from dotenv import load_dotenv
from firecrawl import FirecrawlApp
import google.generativeai as genai

load_dotenv()

firecrawl = FirecrawlApp(api_key="")
genai.configure(api_key="")
gemini = genai.GenerativeModel(
    model_name="gemini-2.5-flash",
    generation_config=genai.GenerationConfig(temperature=0.1, max_output_tokens=3000),
)

SCRAPE_URL_KEYWORDS = ["developer", "api", "integration", "marketplace", "partner", "github", "pricing", "trial"]

# Scraped directly before search — no need to find via search results
KNOWN_URL_PATTERNS = [
    "https://www.{slug}.com/developers/",
    "https://www.{slug}.com/integrations/",
    "https://www.{slug}.com/marketplace/",
    "https://www.{slug}.com/partners/",
    "https://www.{slug}.com/pricing/",
    "https://docs.{slug}.com/",
    "https://developer.{slug}.com/",
    "https://github.com/{slug}/",
]

PRODUCT_PROFILE_SCHEMA = """{
  "identity": {
    "product_name": string,
    "category": [string],          // SIEM|SOAR|EDR|MDM|UEM|NGFW|Firewall|TIP|OSINT|Cloud Security|Network Security|Email Security|Incident Response|Threat Detection|CDN|Zero Trust|Host-based IDS
    "description": string,         // 1-2 sentence summary
    "deployment_model": [string],  // SaaS|self-hosted|hybrid
    "target_persona": string|null, // e.g. "SOC analyst"
    "supported_standards": [string] // STIX|TAXII|OCSF|CIM|ECS — [] if none
  },
  "marketplace": {
    "available": boolean|null,
    "type": string|null,           // public|private|none
    "url": string|null,
    "virustotal_integration_exists": boolean|null,
    "threat_intel_integrations": [
      {"integration_name": string, "description": string, "link": string|null}
    ],
    "similar_existing_integrations": [
      {"integration_name": string, "description": string, "link": string|null}
    ]
  },
  "developer": {
    "api_available": boolean|null,
    "api_type": string|null,            // REST|GraphQL|webhook|file-based|none
    "api_docs_url": string|null,
    "api_auth_method": string|null,     // API key|OAuth 2.0|Basic Auth|multiple|none
    "api_rate_limits_known": boolean|null,
    "sdk_available": boolean|null,
    "sdk_supported_languages": [string],
    "sdk_docs_url": string|null,
    "third_party_dev_allowed": boolean|null,
    "inhouse_dev_only": boolean|null,
    "air_gap_support": boolean|null,
    "webhook_support": boolean|null
  },
  "partnership": {
    "required_for_development": boolean|null,
    "required_for_publishing": boolean|null,
    "program_name": string|null,
    "program_url": string|null,
    "without_partnership": string|null,
    "with_partnership": string|null,
    "self_publish_path": string|null,
    "repository": string|null,
    "existing_gti_or_google_relationship": boolean|null
  },
  "integration_capabilities": {
    "core_capabilities": [string],      // product's own terms, 2-5 words each
    "supported_ioc_types": [string],    // IP|CIDR|Domain|URL|File Hash|ASN|CVE
    "integration_model": string|null,   // connector/agent|feed/pull|API push|file-based|config-only
    "inbound_feed_support": string|null, // STIX/TAXII|custom API|file-based|config-only|none
    "alert_ingestion_supported": boolean|null,
    "playbook_automation": boolean|null,
    "real_time_ingestion": boolean|null,
    "enrichment_supported": boolean|null,
    "bidirectional_support": boolean|null,
    "entry_limit_constraints": string|null
  },
  "trial": {
    "available": boolean|null,
    "type": string|null,           // self-serve|sales-assisted|demo only|none
    "duration_days": integer|null,
    "limitations": string|null,
    "demo_available": boolean|null,
    "demo_link": string|null
  },
  "sources_used": [string]
}"""

EXTRACTION_PROMPT = """You are a security product analyst. Extract a structured product profile from the research content below.

Rules:
- Use ONLY information present in the research content. Do not hallucinate.
- Unknown fields → null. Ambiguous fields → "unknown".
- Return ONLY valid JSON. No prose, no markdown fences.

Product: {product}

Output schema:
{schema}

Research content:
{content}"""

NULL_CHECK_FIELDS = {
    "virustotal_integration_exists": ("marketplace", "{product} VirusTotal integration site"),
    "inbound_feed_support":          ("integration_capabilities", "{product} external threat feed STIX TAXII ingest"),
    "trial":                         ("trial", "{product} free trial demo sandbox"),
    "api_available":                 ("developer", "{product} REST API developers documentation"),
    "third_party_dev_allowed":       ("developer", "{product} third party integration build custom connector"),
    "required_for_publishing":       ("partnership", "{product} partner program publish integration listing"),
    "core_capabilities":             ("integration_capabilities", "{product} threat intelligence features capabilities"),
    "deployment_model":              ("identity", "{product} deployment cloud on-premise SaaS self-hosted"),
}


def search(query: str, limit: int = 5) -> list[dict]:
    try:
        result = firecrawl.search(query, limit=limit)
        items = result.data if hasattr(result, "data") else (result if isinstance(result, list) else [])
        return [
            {
                "url":     getattr(r, "url",      r.get("url",      "")) if not isinstance(r, dict) else r.get("url", ""),
                "title":   getattr(r, "title",    r.get("title",    "")) if not isinstance(r, dict) else r.get("title", ""),
                "content": getattr(r, "markdown", r.get("markdown", getattr(r, "description", ""))) if not isinstance(r, dict) else r.get("markdown", r.get("description", "")),
            }
            for r in items
        ]
    except Exception as e:
        print(f"  [search error] {e}")
        return []


def scrape(url: str) -> str:
    try:
        result = firecrawl.scrape(url, formats=["markdown"], only_main_content=True)
        return (getattr(result, "markdown", None) or result.get("markdown", "") if isinstance(result, dict) else "")
    except Exception as e:
        print(f"  [scrape error] {url}: {e}")
        return ""


def extract(product: str, chunks: list[str]) -> dict:
    combined = "\n\n---\n\n".join(chunks)
    if len(combined) > 200_000:
        combined = combined[:200_000] + "\n[truncated]"
    prompt = EXTRACTION_PROMPT.format(product=product, schema=PRODUCT_PROFILE_SCHEMA, content=combined)
    raw = gemini.generate_content(prompt).text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError as e:
        print(f"  [parse error] {e}")
        return {}


def vendor_slug(product: str) -> str:
    # best-effort: first meaningful word lowercased, strip common suffixes
    stop = {"networks", "systems", "security", "software", "technologies", "cloud", "inc", "labs"}
    words = [w.lower() for w in product.split() if w.lower() not in stop]
    return words[0] if words else product.split()[0].lower()


def known_urls(product: str) -> list[str]:
    slug = vendor_slug(product)
    return [p.format(slug=slug) for p in KNOWN_URL_PATTERNS]


def null_fields(profile: dict) -> list[tuple[str, str]]:
    missing = []
    for field, (parent, query_tpl) in NULL_CHECK_FIELDS.items():
        block = profile.get(parent, {}) if parent != field else profile
        v = block.get(field) if isinstance(block, dict) else None
        if v is None or v == "" or v == "unknown" or v == []:
            missing.append((field, query_tpl))
    return missing


def run(product: str) -> dict:
    print(f"\n── Profiling: {product} ──")
    chunks, search_results = [], []

    # Step 1 — direct scrape of known URLs (no search needed)
    print("[ Scrape ] Known URLs...")
    for url in known_urls(product):
        print(f"  → {url}")
        md = scrape(url)
        if md:
            chunks.append(f"# Scraped: {url}\n\n{md[:8000]}")
        time.sleep(0.3)

    # Step 2 — 4 targeted search queries
    pass1_queries = [
        f"{product} features overview deployment",
        f"{product} marketplace integrations threat intelligence partners",
        f"{product} REST API developer documentation authentication",
        f"{product} technology partner program publish integration",
    ]
    print("[ Search ] Pass 1...")
    for q in pass1_queries:
        print(f"  → {q}")
        results = search(q, limit=5)
        search_results.extend(results)
        for r in results:
            if r["content"]:
                chunks.append(f"# {r['title']}\n{r['url']}\n\n{r['content']}")
        time.sleep(0.4)

    # Step 3 — scrape high-value URLs surfaced by search (not already scraped)
    already = {c.split("\n")[0].replace("# Scraped: ", "") for c in chunks if c.startswith("# Scraped:")}
    extra_urls = [
        r["url"] for r in search_results
        if r["url"] not in already
        and any(k in r["url"].lower() for k in SCRAPE_URL_KEYWORDS)
    ]
    for url in list(dict.fromkeys(extra_urls))[:4]:
        print(f"  → scrape {url}")
        md = scrape(url)
        if md:
            chunks.append(f"# Scraped: {url}\n\n{md[:8000]}")
        time.sleep(0.3)

    # Step 4 — extract pass 1
    print("[ Extract ] Pass 1...")
    profile = extract(product, chunks)

    # Step 5 — gap-fill for null fields
    missing = null_fields(profile)
    if missing:
        print(f"[ Pass 2 ] Gap-fill: {[f for f, _ in missing]}")
        for field, query_tpl in missing:
            q = query_tpl.format(product=product)
            print(f"  → {q}")
            results = search(q, limit=4)
            for r in results:
                if r["content"]:
                    chunks.append(f"# {r['title']}\n{r['url']}\n\n{r['content']}")
            time.sleep(0.4)

        print("[ Extract ] Pass 2...")
        profile = extract(product, chunks)

    out_path = f"{product.lower().replace(' ', '_')}_profile.json"
    with open(out_path, "w") as f:
        json.dump(profile, f, indent=2)
    print(f"[ Done ] → {out_path}")
    return profile


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", required=True, help="e.g. 'Splunk SOAR'")
    args = parser.parse_args()
    run(args.product)
