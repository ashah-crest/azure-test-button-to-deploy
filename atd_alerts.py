from typing import List, Dict, Any, Optional, Type, Generator, Tuple

from src import APIError, ResourceNotFoundError
from src.constants import ATDAlertState, ATDAlertResourceType


class Endpoints:
    """API endpoint paths for ATD Alerts."""
    BASE_URL = "https://threatintelligence.googleapis.com"
    VERSION = "/v1beta"
    GET_ALERTS = "/alerts"
    GET_ALERT = "/alerts/{alert_id}"
    GET_ALERT_DOCUMENT = "/alerts/{alert_id}/documents/{document_id}"
    GET_FINDINGS = "/findings"
    GET_FINDING = "/findings/{finding_id}"
    SEARCH_FINDING = "/projects/{project}/findings:search"
    GET_CONFIGURATIONS = "/configurations"
    GET_CONFIGURATION = "/configurations/{configuration_id}"
    FILTER_CONFIG = "?filter={filters}&orderBy={order_by}&pageSize={page_size}&pageToken={page_token}"
    MARK_BENIGN = ":benign"
    MARK_DUPLICATE = ":duplicate"
    MARK_ESCALATE = ":escalate"
    MARK_NOT_ACTIONABLE = ":notActionable"
    MARK_FALSE_POSITIVE = ":falsePositive"
    MARK_READ = ":read"
    MARK_RESOLVED = ":resolve"
    MARK_TRIAGED = ":triage"
    MARK_EXTERNALLY_TRACKED = ":trackExternally"


class AlertObject:
    def __init__(self, data):
        self.name = data.get("name")
        self.alertId = self.name
        self.findings = data.get("findings", [])
        self.state = data.get("state")
        self._map_audit(data.get("audit", {}))
        self.displayName = data.get("displayName")
        self.detail = self._map_detail(data)
        self.duplicateOf = data.get("duplicateOf")
        self.duplicatedBy = data.get("duplicatedBy", [])
        self.etag = data.get("etag")
        self.externalId = data.get("externalId")
        self.aiSummary = data.get("aiSummary")
        self.relevanceAnalysis = data.get("relevanceAnalysis", {})
        self.severityAnalysis = data.get("severityAnalysis", {})
        self.priorityAnalysis = data.get("priorityAnalysis", {})
        self.findingCount = data.get("findingCount")
        self.configurations = [self._extract_id(config) for config in data.get("configurations", [])]

    def _extract_id(self, value: str) -> str:
        return value.rsplit("/", 1)[-1]

    def _map_detail(self, alert: dict) -> dict:
        detail = alert.get("detail", {})
        detail_type = detail.get("detailType")
        if detail_type not in {"initial_access_broker", "data_leak", "insider_threat"}:
            raise ValueError(f"Unknown detailType: {detail_type}")
        type_details = detail.get(self._snake_to_camel(detail_type), {})
        return {
            "type": detail_type,
            "severity": type_details.get("severity"),
            "discoveryDocumentIds": type_details.get("discoveryDocumentIds")
        }

    def _snake_to_camel(self, s: str) -> str:
        if not s:
            return s
        parts = s.split("_")
        return parts[0] + "".join(p.capitalize() for p in parts[1:] if p)

    def _map_audit(self, alert: dict):
        self.createTime = alert.get("createTime")
        self.updateTime = alert.get("updateTime")
        self.creator = alert.get("creator")
        self.updater = alert.get("updater")

    @classmethod
    def from_dict(cls, data):
        return cls(data)


class DocumentObject:
    def __init__(self, doc: dict):
        self.name = doc.get("name")
        self.content = doc.get("content")
        self.author = doc.get("author")
        self.createTime = doc.get("createTime")
        self.languageCode = doc.get("languageCode")
        self.title = doc.get("title")
        self.aiSummary = doc.get("aiSummary")
        self.translation = doc.get("translation")
        self.source = doc.get("source")
        self.sourceUri = doc.get("sourceUri")
        self.ingestTime = doc.get("ingestTime")
        self.collectionTime = doc.get("collectionTime")
        self.sourceUpdateTime = doc.get("sourceUpdateTime")

    @classmethod
    def from_dict(cls, data):
        return cls(data)


class FindingObject:
    def __init__(self, finding: Dict[str, Any]):
        self.name: str = finding.get("name")
        self.provider: str = finding.get("provider")
        self.displayName: str = finding.get("displayName")
        self.detail: Dict[str, Any] = finding.get("detail", {})
        self.severity: Optional[float] = finding.get("severity")
        self.reoccurrenceTimes: List[str] = finding.get("reoccurrenceTimes", [])
        self.relevanceAnalysis: Dict[str, Any] = finding.get("relevanceAnalysis", {})
        self.severityAnalysis: Dict[str, Any] = finding.get("severityAnalysis", {})
        self.aiSummary: str = finding.get("aiSummary")
        self.audit: Dict[str, Any] = finding.get("audit", {})
        self.alert: str = finding.get("alert")
        self.configurations: List[str] = finding.get("configurations", [])

    @classmethod
    def from_dict(cls, data):
        return cls(data)


class ConfigurationObject:
    def __init__(self, config: Dict[str, Any]):
        self.name: str = config.get("name")
        self.displayName: str = config.get("displayName")
        self.audit: Dict[str, Any] = config.get("audit", {})
        self.provider: str = config.get("provider")
        self.state: str = config.get("state")
        self.detail: Dict[str, Any] = config.get("detail", {})
        self.version: str = config.get("version")
        self.description: str = config.get("description")

    @classmethod
    def from_dict(cls, data):
        return cls(data)


class ATDAlerts:
    """
    GTI ATD Alerts SDK
    - Token fully managed inside this class
    - Uses client.session (no session duplication)
    - Handles TI auth + refresh on 401
    - pageToken pagination
    """
    def __init__(self, client, project_id):
        self._client = client
        self._token = None
        self._projectId = project_id

    # ---------------------------------------------------------
    # TOKEN MANAGEMENT (ATD-LOCAL)
    # ---------------------------------------------------------
    def _get_token(self, force_refresh=False):

        if self._token and not force_refresh:
            return self._token

        self._client.session.headers.update({
            "Content-Type": "application/json"
        })
        response = self._client.post_json(
            "https://idp.prod.identity.proactive.virustotal.com/realms/master/exchange/api-key",
            json_data={"api_key": self._client._apikey}
        )

        # assumes standard TI auth response
        self._token = response.get("access_token")

        return self._token

    def _reset_token(self):
        self._token = None

    # ---------------------------------------------------------
    # HEADERS
    # ---------------------------------------------------------
    def _headers(self):
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "x-goog-user-project": self._projectId
        }

    # ---------------------------------------------------------
    # INTERNAL REQUEST WRAPPER (handles 401 refresh)
    # ---------------------------------------------------------
    def _request(self, method, url, **kwargs):

        headers = kwargs.get("headers", {})
        headers.update(self._headers())
        kwargs["headers"] = headers
        response = self._client.session.request(method, url, **kwargs)

        # -----------------------------------------------------
        # TOKEN EXPIRED HANDLING
        # -----------------------------------------------------
        if getattr(response, "status_code", None) == 401:
            self._reset_token()
            headers = self._headers()
            kwargs["headers"] = headers
            response = self._client.session.request(method, url, **kwargs)

        response_json = response.json()
        if response_json.get("error") is not None:
            error_code = response_json.get("error").get("code")
            error_status = response_json.get("error").get("status")
            raise APIError(f"API Error {error_status}", response_json.get("error").get("message"), error_code)
        return response.json()


    # ---------------------------------------------------------
    # Triage Alerts
    # ---------------------------------------------------------
    def triage_alert(self, alert_name: str, triage: ATDAlertState) -> AlertObject:
        url = f"{Endpoints.BASE_URL}{Endpoints.VERSION}{alert_name}"
        action = ""
        match triage:
            case ATDAlertState.BENIGN:
                action = Endpoints.MARK_BENIGN
            case ATDAlertState.DUPLICATE:
                action = Endpoints.MARK_DUPLICATE
            case ATDAlertState.ESCALATED:
                action = Endpoints.MARK_ESCALATE
            case ATDAlertState.FALSE_POSITIVE:
                action = Endpoints.MARK_FALSE_POSITIVE
            case ATDAlertState.NOT_ACTIONABLE:
                action = Endpoints.MARK_NOT_ACTIONABLE
            case ATDAlertState.READ:
                action = Endpoints.MARK_READ
            case ATDAlertState.RESOLVED:
                action = Endpoints.MARK_RESOLVED
            case ATDAlertState.TRIAGED:
                action = Endpoints.MARK_TRIAGED
            case ATDAlertState.TRACKED_EXTERNALLY:
                action = Endpoints.MARK_EXTERNALLY_TRACKED

        url = url + action
        response = self._request(
            "POST",
            url
        )
        return AlertObject.from_dict(response)

    def get_alert_resource(self, alert_id: str, resource_type: str):
        alert = self.get_alert(alert_id)
        if resource_type == ATDAlertResourceType.DOCUMENTS:
            list_ids = alert.detail.get("discoveryDocumentIds", [])
            return self.get_alert_documents(list_ids)
        elif resource_type == ATDAlertResourceType.FINDINGS:
            list_ids = alert.findings
            return self.get_alert_findings(list_ids)
        elif resource_type == ATDAlertResourceType.CONFIGURATIONS:
            list_ids = alert.configurations
            return self.get_alert_findings(list_ids)
        else:
            return None

    def get_alert_documents(self, document_ids: List[str]) -> List[DocumentObject]:
        """
        Fetch all documents for a given alert.
        """
        # extract document IDs from union detail
        documents: List[DocumentObject] = []
        for doc_id in document_ids:
            document = self.get_document(doc_id)
            documents.append(document)
        return documents

    def get_alert_findings(self, finding_ids: List[str]) -> List[FindingObject]:
        """
        Fetch all findings for a given alert.
        """
        findings: List[FindingObject] = []
        for finding_id in finding_ids:
            finding = self.get_finding(finding_id)
            findings.append(finding)
        return findings

    def get_alert_configurations(self, config_ids: List[str]) -> List[ConfigurationObject]:
        """
        Fetch all configurations for a given alert.
        """
        configurations: List[ConfigurationObject] = []
        for config_id in config_ids:
            config_id = self.get_configuration(config_id)
            configurations.append(config_id)
        return configurations

    def _list_resources_iter(
            self, path: str, object_class: Type, page_size: int, page_token: str, order_by: str, filters: str
    ) -> Generator[Any, None, None]:
        """
        Generic method for paginated resources (alerts, findings, configurations)
        """
        params = {}
        url = f"{Endpoints.BASE_URL}{Endpoints.VERSION}/projects/{self._projectId}{path}"
        while True:
            configs = Endpoints.FILTER_CONFIG.format(page_size=page_size, page_token=page_token, order_by=order_by, filters=filters)
            response = self._request("GET", url+configs, params=params)
            key = list(response.keys())[0]
            for item in response.get(key, []):
                yield object_class(item)
            page_token = response.get("nextPageToken")
            if not page_token:
                break

    def _list_resources(self, path: str, object_class: Type, page_size: int, page_token:str, order_by: str, filters: str) -> tuple[list[Any], Any]:
        """
        Generic method for paginated resources (alerts, findings, configurations)
        """
        params = {}
        url = f"{Endpoints.BASE_URL}{Endpoints.VERSION}/projects/{self._projectId}{path}"
        configs = Endpoints.FILTER_CONFIG.format(page_size=page_size, page_token=page_token, order_by=order_by,
                                                 filters=filters)
        response = self._request("GET", url+configs, params=params)
        key = list(response.keys())[0]
        items = [object_class(i) for i in response.get(key, [])]
        next_token = response.get("nextPageToken")
        return items, next_token

    def list_alerts(self, page_size: Optional[int] = 10, page_token: Optional[str] = "", order_by: Optional[str] = "",
                    filters: Optional[str] = "") -> tuple[list[AlertObject], Any]:
        return self._list_resources(Endpoints.GET_ALERTS, object_class=AlertObject, page_size=page_size,
                                    page_token=page_token, order_by=order_by, filters=filters)

    def list_alerts_iterator(self, page_size: Optional[int] = 10, page_token: Optional[str] = "", order_by: Optional[str] = "",
                             filters: Optional[str] = "") -> Generator[AlertObject, None, None]:
        return self._list_resources_iter(Endpoints.GET_ALERTS, object_class=AlertObject, page_size=page_size,
                                         page_token=page_token, order_by=order_by, filters=filters)

    def list_findings(self, page_size: Optional[int] = 10, page_token: Optional[str] = "", order_by: Optional[str] = "",
                      filters: Optional[str] = "") -> tuple[list[FindingObject], Any]:
        return self._list_resources(Endpoints.GET_FINDINGS, object_class=FindingObject, page_size=page_size,
                                    page_token=page_token, order_by=order_by, filters=filters)

    def list_findings_iterator(self, page_size: Optional[int] = 10, page_token: Optional[str] = "", order_by: Optional[str] = "",
                      filters: Optional[str] = "") -> Generator[FindingObject, None, None]:
        return self._list_resources_iter(Endpoints.GET_FINDINGS, object_class=FindingObject, page_size=page_size,
                                    page_token=page_token, order_by=order_by, filters=filters)

    def list_configurations(self, page_size: Optional[int] = 10, page_token: Optional[str] = "", order_by: Optional[str] = "",
                      filters: Optional[str] = "") -> tuple[list[ConfigurationObject], Any]:
        return self._list_resources(Endpoints.GET_CONFIGURATIONS, object_class=ConfigurationObject, page_size=page_size,
                                    page_token=page_token, order_by=order_by, filters=filters)

    def list_configurations_iterator(self, page_size: Optional[int] = 10, page_token: Optional[str] = "", order_by: Optional[str] = "",
                      filters: Optional[str] = "") -> Generator[ConfigurationObject, None, None]:
        return self._list_resources_iter(Endpoints.GET_CONFIGURATIONS, object_class=ConfigurationObject,
                                         page_size=page_size,page_token=page_token, order_by=order_by, filters=filters)

    def _get_data(self, path: str):
        url = f"{Endpoints.BASE_URL}{Endpoints.VERSION}/{path}"
        return self._request("GET", url)

    def get_alert(self, alert_name: str) -> AlertObject:
        data = self._get_data(alert_name)
        return AlertObject.from_dict(data)

    def get_finding(self, finding_id: str) -> FindingObject:
        data = self._get_data(finding_id)
        return FindingObject.from_dict(data)

    def get_document(self, document_id: str) -> DocumentObject:
        data = self._get_data(document_id)
        return DocumentObject.from_dict(data)

    def get_configuration(self, configuration_id: str) -> ConfigurationObject:
        data = self._get_data(Endpoints.GET_CONFIGURATION.format(configuration_id=configuration_id))
        return ConfigurationObject.from_dict(data)
