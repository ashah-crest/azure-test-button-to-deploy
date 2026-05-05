#   

# 

# 

# 

# 

# 

# 

# 

# GTI Integration with Maltego

## Technical Design and Documentation

**Version Control**

# ---

| \# | Document Version | Date | Owner | Document Status | Comments |
| :---- | :---- | :---- | :---- | :---- | :---- |
| 1 | 1.0.0 | 29/01/2026 | Crest Data  | Draft |  |

# 

**Table of Contents**

# ---

[**Overview	3**](#overview)

[Google Threat Intelligence (GTI) Platform	3](#google-threat-intelligence-\(gti\)-platform)

[Maltego	3](#maltego)

[GTI integration for Maltego	3](#gti-integration-for-maltego)

[**Compatibility Matrix	4**](#compatibility-matrix)

[**Data Flow Diagram	5**](#data-flow-diagram)

[**Integration Use Cases	6**](#integration-use-cases)

[**Low Level – Technical Approach	8**](#low-level-–-technical-approach)

[Project Directory Structure	8](#project-directory-structure)

[Execution Flow (Asynchronous Request/Response)	8](#execution-flow-\(asynchronous-request/response\))

[API Key Management	9](#api-key-management)

[**GTI API Information	10**](#gti-api-information)

[Core Endpoints	10](#core-endpoints)

[**Service Information	11**](#service-information)

[Maltego-Transform (Python SDK)	11](#maltego-transform-\(python-sdk\))

[GTI / VirusTotal API	11](#gti-/-virustotal-api)

[**Configuration	12**](#configuration)

[Required details (Environment Variables)	12](#required-details-\(environment-variables\))

[Error message details for required fields	12](#error-message-details-for-required-fields)

[**Error Handling	13**](#error-handling)

[**Limitations	14**](#limitations)

[Maltego limitations:	14](#maltego-limitations:)

[Data Currency:	14](#data-currency:)

[**Assumptions	15**](#assumptions)

[**References	16**](#references)

# 

# **Overview** {#overview}

# ---

## Google Threat Intelligence (GTI) Platform {#google-threat-intelligence-(gti)-platform}

Google Threat Intelligence provides a comprehensive and proactive approach to identifying, analyzing, and mitigating security threats. Leveraging Google’s vast infrastructure, global telemetry, and advanced analytics, it delivers actionable insights to enhance an organization’s security posture. Google Threat Intelligence offers capabilities such as threat detection, analysis of malware and phishing campaigns, real-time threat alerts, and intelligence feeds that integrate seamlessly with security tools like SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response) platforms.

## Maltego {#maltego}

Maltego is a powerful investigative and link-analysis platform used by security analysts, threat hunters, and investigators to identify, visualize, and analyze relationships across people, infrastructure, domains, IPs, malware, and other entities. It uses a graph-based interface and “transforms” to pull data from multiple internal and external sources, enabling users to pivot from one data point to another and uncover hidden connections. Maltego is widely used for threat intelligence analysis, incident response, fraud investigations, and digital forensics because it turns complex datasets into clear, visual intelligence that supports faster and more accurate decision-making.

## GTI integration for Maltego {#gti-integration-for-maltego}

This project involves building a custom Maltego Transform set using the Maltego TRX Python library. These transforms will allow investigators to query the GTI (VirusTotal) API directly from the Maltego graph.

* **Goal**: Enable over 45 distinct investigative actions (transforms) to enrich entities.  
* **Deployment**: The integration will be deployed as remote Transform Server, adhering to the standard Maltego TRX server specification.

# 

# 


# 	

# **Compatibility Matrix** {#compatibility-matrix}

# ---

| Component | Version Requirement |
| :---- | :---- |
| Maltego Client | v4.2.0 or higher (CE, Classic, or XL) |
| Python | v3.12+ |
| Maltego Transform library | v3.2.0+ |
| GTI API | v3 (Standard or Premium/Enterprise tiers) |

# 

# **Data Flow Diagram** {#data-flow-diagram}

# ---

The architecture follows a standard synchronous Request/Response model compliant with the Maltego TDS (Transform Distribution Server) protocol.

1. User runs a transform (e.g., "To Communicating Files") on an IP Entity.  
2. Maltego Client sends an JSON request to the configured TDS.  
3. TDS forwards the request to our Python Transform Server (hosting the TRX code).  
4. Transform Server parses the input, authenticates via API Key, and queries the GTI API endpoints.  
5. GTI API returns JSON threat data.  
6. Transform Server parses the JSON and constructs Maltego Entities (e.g., File hashes) with properties.  
7. Maltego Client renders the new entities on the graph.

# 

# **Integration Use Cases** {#integration-use-cases}

# ---

Given the scope of actions, use cases are categorized by Entity Type.  
[Maltego-GTI entity details](https://docs.google.com/spreadsheets/d/190jn9HOv_t5-RopkBFM_9exusAi17dhA060Zvf2KcOk/edit?usp=sharing)

**Acceptance Criteria**

1. Transforms must correctly identify the input entity type.  
2. Transforms must gracefully handle "Not Found" (404) responses without crashing the graph.

These transforms run on a specific indicator (like a URL, IP, Domain, File or Hash) to retrieve detailed reports and attributes about it.

* **To Outgoing Links** (Input: `URL`)**:** Returns other `URL` entities that the input URL links to.  
* **To AS Number** (Input: `IPv4Address`): Returns the `AS` (Autonomous System) entity, including the AS number and owner.  
* **To Subnet** (Input: `IPv4Address`)**:** Returns the `CIDR` network subnet that the IP address belongs to.  
* **To Last DNS Records** (Input: `Domain`, `DNSName`)**:** Returns various DNS record entities (`A`, `AAAA`, `NS`, `MX`, etc.) from the last known resolution.  
* **To Filenames** (Input: `File`, `Hash`): Returns `Phrase` entities representing all known filenames for the given file or hash.  
* **To Hash** (Input: `File`)**:** Returns a `Hash` entity containing the MD5, SHA1, and SHA256 hashes of the input file.  
* **To File** (Input: `Hash`)**:** Returns a detailed `GTIFile` entity with rich data including multiple hashes (SHA256, hash, sha1), file size, creation dates, submission stats, and reputation.  
* **To File Type** (Input: `File`, `Hash`)**:** Returns a `GTIFileType` entity representing the file's type (e.g., "exe", "pdf", "dll").  
* **To EXIFTool Info** (Input: `File`, `Hash`)**:** Returns a `GTIEXIFToolInfo` entity containing all available EXIF metadata from the file.  
* **To Tags** (Input: `URL`, `IP`, `Domain`, `Hash`, etc.): Returns `Tag` entities that GTI uses to classify the indicator (e.g., `malware`, `c2`).  
* **To Categories** (Input: `URL`, `Domain`)**:** Returns `Phrase` entities representing security vendor classifications (e.g., "phishing", "malware").  
* **To Last SSL Certificate** (Input: `Domain`, `IP`)**:** Returns an `X509Certificate` entity with full details of the last seen SSL certificate, including issuer, subject, and alternative names.

Relationship Transforms:  
These transforms take an indicator and find related high-level threat intelligence objects. Supported for all the input indicators (like a URL, IP, Domain, File or Hash).

* **To Get Reports:** Returns `STIX2report` entities. These are rich OSINT and threat reports from Google, partners, and researchers that mention the indicator. The report entity includes timelines, targeted regions/industries, IOC counts, and more.  
* **To Get Campaigns:** Returns `STIX2campaign` entities. This links the indicator to known threat campaigns, providing details on the campaign's objective, aliases, first/last seen dates, and targeted victims.  
* **To Get IOC Collections:** Returns `GTIIOCCollection` entities. These are curated collections of indicators that are thematically related. The entity includes IOC counts, first/last seen dates, and targeted regions/industries.  
* **To Get Malware Families:** Returns `MalwareFamily` entities associated with the indicator. The entity includes the family's name, category (e.g., `dropper`, `RAT`), targeted platforms, and extensive metadata on targets and sightings.  
* **To Get Software Toolkit:** Returns `STIX2tool` entities. This links an indicator to known software (e.g., `mimikatz`, `cobalt_strike`), providing details on its type, aliases, and associated threat data.  
* **To Get Threat Actors:** Returns `STIX2threatactor` entities (e.g., `APT29`, `FIN7`). The entity is enriched with the actor's motivations, goals, known aliases, first/last seen dates, and targeted victim profiles.  
* **To Get Vulnerabilities:** Returns `CVE` entities linked to the indicator's use in exploitation. The entity is highly detailed, containing CVSS/EPSS scores, exploitation state, disclosure timelines, and links to NVD/MITRE.

# **Low Level – Technical Approach** {#low-level-–-technical-approach}

# ---

### Project Directory Structure {#project-directory-structure}

The solution will follow the standard maltego-trx library structure, with an additional module for the core API logic to handle the high volume of transforms (actions) cleanly.

### Execution Flow (Asynchronous Request/Response) {#execution-flow-(asynchronous-request/response)}

This transform server uses the modern, asynchronous `maltego-transforms` library. Here is the typical request/response lifecycle:

* **Incoming Request:** The Maltego Client sends an HTTP POST request to the server. The run\_server function in project.py manages an underlying asynchronous web server that listens for these requests.  
* **Deserialization & Routing:** The maltego-transforms library automatically deserializes the request body into Python objects: a MaltegoEntity for the input, a settings dictionary containing the API key, and a MaltegoContext object for logging. It then routes the request to the correct asynchronous function in the transforms/ directory that is decorated with @register\_transform.  
* **Asynchronous API Interaction:** The transform function (e.g., to\_reports) is executed. It calls get\_gti\_client() to retrieve an async HTTP client and makes a non-blocking HTTPS request to the Google Threat Intelligence API, awaiting the response.  
* **Response Generation (Streaming):** The transform parses the JSON response from the GTI API. For each result, it constructs a new MaltegoEntity object (like STIX2report or CVE). Instead of appending to a static list, the function uses yield to stream each new entity back to the server as it's created.  
* **Serialization & Response:** The maltego-transforms library gathers all the yielded entities, serializes them into the final Maltego response format, and sends it back to the client in a single HTTP response.

### API Key Management {#api-key-management}

* Transform Settings (TRX TransformSettings). This allows individual analysts to input their own keys in the Maltego Client pop-up if the server is shared.

# 

# **GTI API Information** {#gti-api-information}

# ---

### Core Endpoints {#core-endpoints}

* **Files:** https://www.virustotal.com/api/v3/files/{id}  
* **URLs:** https://www.virustotal.com/api/v3/urls/{id}  
* **Domains:** https://www.virustotal.com/api/v3/domains/{domain}  
* **IP Addresses:** https://www.virustotal.com/api/v3/ip\_addresses/{ip}  
* **Objects related to a file:** https://www.virustotal.com/api/v3/files/{id}/{relationship}  
* **Objects related to a URL:** https://www.virustotal.com/api/v3/urls/{id}/{relationship}  
* **Objects related to a domain:** https://www.virustotal.com/api/v3/domains/{domain}/{relationship}  
* **Objects related to an IP address:** https://www.virustotal.com/api/v3/ip\_addresses/{ip}/{relationship}

###  

# **Service Information** {#service-information}

# ---

### Maltego-Transform (Python SDK) {#maltego-transform-(python-sdk)}

* The core framework used to define entities and transforms. It handles the serialization of data into the Maltego JSON protocol.

### GTI / VirusTotal API {#gti-/-virustotal-api}

* The external data source.

# 

# **Configuration** {#configuration}

# ---

### Required details (Environment Variables) {#required-details-(environment-variables)}

| Variable | Description | Required? | Default |
| :---- | :---- | :---- | :---- |
| GTI\_API\_KEY | GTI API Key | Yes | N/A |

### Error message details for required fields {#error-message-details-for-required-fields}

If GTI\_API\_KEY is missing on server startup, the application should log a fatal error and exit. If missing during a transform request (if using per-user keys), the transform returns a specific UIM requesting the user to check their Transform Manager settings.

# 

# 

# **Error Handling** {#error-handling}

# ---

The transform code must implement try/except blocks to catch API errors and return "User Information Messages" (UIM) to the Maltego GUI.

| Error Code | GTI Cause | Maltego Response |
| :---- | :---- | :---- |
| **401** | Invalid API Key | Return UIM: "GTI API Key Invalid or Missing." |
| **404** | Object not found | Return UIM: "No data found for this entity." (Do not return an error icon). |
| **429** | Quota Exceeded | Return UIM: "GTI Daily/Minute Quota Exceeded." (Critical Error). |
| **500** | Server Error | Return UIM: "GTI Provider Error. Please try again later." |

# 

# **Limitations** {#limitations}

# ---

### Maltego limitations: {#maltego-limitations:}

| Feature | Maltego Basic (Free) | Maltego Pro | Maltego Enterprise |
| :---- | :---- | :---- | :---- |
| Entities per Transform | 24 | 10,000 | 64,000+ |
| Total Entities per Graph | 10,000 | 1,000,000+ | Unlimited (Hardware dependent) |

### Data Currency:  {#data-currency:}

* Maltego graphs are static snapshots. If GTI data changes, the transform must be re-run to update the entity.

# 

# **Assumptions** {#assumptions}

# ---

1. **API Access:** The end-user or the hosted server possesses a valid VirusTotal API Key with sufficient quota to handle the volume of transforms.  
2. **Connectivity:** The host server has outbound HTTPS access to https://www.virustotal.com/api/v3/.  
3. **Entity Mapping:** Standard Maltego entities (maltego.url, maltego.IPv4, maltego.Domain, maltego.Hash, maltego.File, maltego.DNSname) will be used as input triggers.  
4. **Deployment:** The Maltego transform server will be hosted and managed by the Google team. The transform service will expose a seed URL which will be shared with the Maltego team for integration and onboarding into the Maltego ecosystem.  
5. **Private Transform Library Access:** End users will access the GTI transforms through the **Maltego Private Transform Hub (Private Transform Library)**.

# 

# **References** {#references}

# ---

1. **Maltego TRX Documentation:** https://docs.maltego.com/support/solutions/articles/15000017584-setup-python-transform-server  
2. **VirusTotal API v3 Reference:** https://developers.virustotal.com/reference/overview

   

   

# 

# 

