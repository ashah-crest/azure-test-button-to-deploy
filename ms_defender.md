# Platform Integration Analysis — Microsoft Defender for Endpoint

---

## Platform Overview

- Microsoft Defender for Endpoint is a cloud-native enterprise security platform that provides advanced threat protection, detection, investigation, and automated response across endpoints including PCs, servers, and mobile devices
- Category: EDR / Endpoint Security / Threat Protection
- Delivers vulnerability management, real-time threat detection, and automated response capabilities across Windows, macOS, Linux, Android, and iOS — integrating natively with the broader Microsoft Azure security ecosystem

---

## Feasible GTI Use Cases

- Threat List Ingestion (File Hashes, URLs, Domains, IP Addresses)

---

## Marketplace & Existing Integrations

### Marketplace Availability
- Marketplace available: No
- Marketplace type:
  - None — Microsoft Defender does not support a third-party integration marketplace
  - Integration is deployed directly within the customer's Azure environment using infrastructure-as-code (Bicep templates)

- Integration code is maintained and distributed via:
  - https://github.com/VirusTotal

### Similar Integrations

##### 1. Microsoft Defender Threat Intelligence (MDTI)
Microsoft Defender natively ingests threat intelligence from MDTI to automatically populate custom Indicators of Compromise (IOCs), enabling real-time blocking and alerting across Defender-protected endpoints based on continuously updated threat data.
[Documentation](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)

##### 2. MISP
Microsoft Defender integrates with MISP to pull structured threat intelligence feeds and ingest IOCs as custom indicators, enriching endpoint detection with community-driven and organizationally curated threat data.
[Documentation](https://www.misp-project.org/2022/02/16/MISP-and-Microsoft-Sentinel.html)

---

## Third-Party Integration Publishing

### Development Support
- Third-party development allowed: Yes
- Microsoft Defender does not provide a native integration marketplace or plugin framework — integrations are built externally using Microsoft Defender APIs and deployed via Azure infrastructure

### Contribution / Publishing Path
- Publishing method:
  - GitHub / Repository contribution via VirusTotal GitHub
  - Integration code and Bicep deployment templates published to the VirusTotal repository for customer access and deployment

- PR Contribution supported: Yes

- If Yes:
  - Repo: https://github.com/VirusTotal

---

### Partnership Requirement

**Is partnership required?**
- No

**Without partnership:**
- Build and deploy custom integrations using Microsoft Defender and Azure APIs
- Publish integration code and deployment templates via VirusTotal GitHub repository
- Customers deploy directly into their own Azure environment using provided Bicep templates
- Full control over integration logic, configuration, and Azure resource lifecycle

---

## Trial Access & Testing

### Availability
- Yes

### Options
- Microsoft Defender for Endpoint E5 license (enterprise trial available)

---

## Proposal Details
- Proposal Status: Approved

### Key Feedback:
- GTI integration aligns strongly with Defender's custom IOC ingestion model via the Microsoft Security API
- Proposed integration should cover Threat List Ingestion including file hashes, URLs, domains, and IP addresses
- Integration leverages Azure-native infrastructure (Azure Function, Key Vault, Table Storage) with a Bicep template provided for streamlined, repeatable customer deployments
- Aligns with established IOC ingestion patterns used by MDTI and MISP integrations
- Azure Function-based orchestration provides a serverless, cost-effective, and maintainable approach for periodic threat intelligence synchronization

---

## Integration Approach (How to Build)

* Integration code is published to the **VirusTotal GitHub repository** — customers clone the repository and deploy using the provided **Azure Bicep template**
* Bicep template provisions the complete Azure resource stack in a single deployment step — **Azure Function App, Key Vault, Table Storage, and Managed Identity**
* A **TimerTrigger Azure Function** acts as the orchestration core, executing on a configurable CRON schedule (e.g., every hour)
* On each run, the function securely retrieves API credentials from **Azure Key Vault** via Managed Identity and reads operational parameters (Threat Lists, Severity, Verdict, Threat Score, Lookback Days) from **Function App Application Settings**
* The function polls the **GTI Threat Lists API** for the latest IOCs — using a **checkpoint stored in Azure Table Storage** to fetch only new records since the last execution, preventing duplicate ingestion
* Fetched IOCs are filtered against configured Severity, Verdict, and Threat Score thresholds — only qualifying records are passed forward
* Filtered records are transformed and mapped into the **Microsoft Defender Indicator schema** (`indicatorValue`, `indicatorType`, `action`, `severity`, `expirationDateTime`, etc.)
* Transformed IOCs are submitted in **batches of 500** to the Microsoft Defender Security API via POST to `https://api.security.microsoft.com/api/indicators/import`
* If the **15,000 indicator capacity cap** is reached, ingestion halts immediately and the checkpoint is **not updated** — ensuring no data loss on the next execution cycle
* On successful completion, the **Checkpoint table is updated** with the latest processed timestamp for incremental sync on the next run
* Ingested IOCs are active within the Defender tenant — continuously evaluated against endpoint telemetry to trigger configured **Alert or Block actions** until expiration

---

### Developer Resources
- APIs available: Yes
- Documentation: Available

#### Official Documentation References
- Microsoft Defender Indicators Import API: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/ti-indicator
- Microsoft Defender for Endpoint API Documentation: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/apis-intro
- Azure Bicep Documentation: https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/overview
- Azure Function Developer Guide: https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference
- Azure Key Vault Developer Guide: https://learn.microsoft.com/en-us/azure/key-vault/general/developers-guide
- VirusTotal GitHub Repository: https://github.com/VirusTotal

---

## Challenges & Blockers
- Microsoft Defender does not support a native marketplace or plugin framework — no self-service integration distribution model available
- Microsoft Defender enforces a **15,000 active indicator cap** per tenant — requires capacity monitoring and ingestion halt logic to prevent data loss
- Batch ingestion (500 IOCs per API call) introduces processing overhead for large threat list volumes
- Checkpoint and state management logic required to ensure accurate incremental syncs and prevent duplicate IOC ingestion

---

## Summary & Recommendations
- Yes, the integration is fully feasible

Microsoft Defender for Endpoint supports GTI integration through its **custom Indicators of Compromise (IOC) ingestion API**, operationalizing GTI threat intelligence directly within Defender-protected endpoint environments.

- Microsoft Defender does not offer a native marketplace — integration is deployed directly into the customer's Azure environment via a provided **Bicep deployment template** for streamlined, repeatable provisioning
- Integration code is published and maintained in the **VirusTotal GitHub repository**, making it accessible to customers without any marketplace dependency
- Azure-native serverless architecture (Azure Function, Key Vault, Table Storage) provides a scalable, secure, and cost-effective deployment model
- Bicep template abstracts infrastructure complexity — customers can deploy the full integration stack in a single step with minimal configuration overhead
- Checkpoint-based state management ensures accurate incremental ingestion and eliminates duplicate processing
- No dependency on vendor partnership or marketplace onboarding