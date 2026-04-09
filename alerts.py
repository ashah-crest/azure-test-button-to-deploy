"""Alerts endpoints for GTI API - DTM and ASM alerts."""

import enum
import re
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Union

from ..constants import (
    DEFAULT_ALERTS_PAGE_SIZE,
    MAX_DTM_ALERTS_PAGE_SIZE,
    MAX_ASM_ALERTS_PAGE_SIZE,
    DEFAULT_ASM_PAGE_SIZE,
    DTMAlertEndpoints,
    ASMEndpoints,
    DTMAlertSortField,
    DTMAlertSortOrder,
    DTMAlertStatus,
    DTMAlertType,
    DTMAlertSeverity,
    ASMIssueStatus,
    ASMEntityType,
)
from ..exceptions import (
    APIError,
    InvalidParameterError,
    InvalidLimitError,
    ResourceNotFoundError,
    DTMAlertError,
    ASMAlertError,
)

if TYPE_CHECKING:
    from ..client import Client


# =============================================================================
# DTM Alert Enums (Public API)
# =============================================================================


class AlertSortField(enum.Enum):
    """Sort fields for DTM alerts."""

    ID = DTMAlertSortField.ID
    CREATED_AT = DTMAlertSortField.CREATED_AT
    UPDATED_AT = DTMAlertSortField.UPDATED_AT
    MONITOR_ID = DTMAlertSortField.MONITOR_ID


class AlertSortOrder(enum.Enum):
    """Sort order for DTM alerts."""

    ASC = DTMAlertSortOrder.ASC
    DESC = DTMAlertSortOrder.DESC


class AlertStatus(enum.Enum):
    """Status values for DTM alerts."""

    NEW = DTMAlertStatus.NEW
    READ = DTMAlertStatus.READ
    CLOSED = DTMAlertStatus.CLOSED
    ESCALATED = DTMAlertStatus.ESCALATED
    IN_PROGRESS = DTMAlertStatus.IN_PROGRESS
    NO_ACTION_REQUIRED = DTMAlertStatus.NO_ACTION_REQUIRED
    DUPLICATE = DTMAlertStatus.DUPLICATE
    NOT_RELEVANT = DTMAlertStatus.NOT_RELEVANT
    TRACKED_EXTERNAL = DTMAlertStatus.TRACKED_EXTERNAL


class AlertType(enum.Enum):
    """Alert type values for DTM alerts."""

    COMPROMISED_CREDENTIALS = DTMAlertType.COMPROMISED_CREDENTIALS
    DOMAIN_DISCOVERY = DTMAlertType.DOMAIN_DISCOVERY
    FORUM_POST = DTMAlertType.FORUM_POST
    MESSAGE = DTMAlertType.MESSAGE
    PASTE = DTMAlertType.PASTE
    SHOP_LISTING = DTMAlertType.SHOP_LISTING
    TWEET = DTMAlertType.TWEET
    WEB_CONTENT = DTMAlertType.WEB_CONTENT


class AlertSeverity(enum.Enum):
    """Severity values for DTM alerts."""

    HIGH = DTMAlertSeverity.HIGH
    MEDIUM = DTMAlertSeverity.MEDIUM
    LOW = DTMAlertSeverity.LOW


# =============================================================================
# ASM Issue Enums (Public API)
# =============================================================================


class IssueStatus(enum.Enum):
    """Status values for ASM issues."""

    # Open statuses
    OPEN_TRIAGED = ASMIssueStatus.OPEN_TRIAGED
    OPEN_IN_PROGRESS = ASMIssueStatus.OPEN_IN_PROGRESS

    # Closed statuses
    CLOSED_MITIGATED = ASMIssueStatus.CLOSED_MITIGATED
    CLOSED_RESOLVED = ASMIssueStatus.CLOSED_RESOLVED
    CLOSED_DUPLICATE = ASMIssueStatus.CLOSED_DUPLICATE
    CLOSED_OUT_OF_SCOPE = ASMIssueStatus.CLOSED_OUT_OF_SCOPE
    CLOSED_BENIGN = ASMIssueStatus.CLOSED_BENIGN
    CLOSED_RISK_ACCEPTED = ASMIssueStatus.CLOSED_RISK_ACCEPTED
    CLOSED_FALSE_POSITIVE = ASMIssueStatus.CLOSED_FALSE_POSITIVE
    CLOSED_NO_REPRODUCE = ASMIssueStatus.CLOSED_NO_REPRODUCE
    CLOSED_TRACKED_EXTERNALLY = ASMIssueStatus.CLOSED_TRACKED_EXTERNALLY


class EntityType(enum.Enum):
    """Entity types for ASM issues."""

    API_ENDPOINT = ASMEntityType.API_ENDPOINT
    APP_ENDPOINT = ASMEntityType.APP_ENDPOINT
    AUTONOMOUS_SYSTEM = ASMEntityType.AUTONOMOUS_SYSTEM
    AWS_EC2_INSTANCE = ASMEntityType.AWS_EC2_INSTANCE
    AWS_RDS_DB_INSTANCE = ASMEntityType.AWS_RDS_DB_INSTANCE
    AWS_S3_BUCKET = ASMEntityType.AWS_S3_BUCKET
    AZURE_STORAGE_ACCOUNT = ASMEntityType.AZURE_STORAGE_ACCOUNT
    AZURE_VIRTUAL_MACHINE = ASMEntityType.AZURE_VIRTUAL_MACHINE
    DNS_RECORD = ASMEntityType.DNS_RECORD
    DOMAIN = ASMEntityType.DOMAIN
    EMAIL_ADDRESS = ASMEntityType.EMAIL_ADDRESS
    GCP_API_GATEWAY = ASMEntityType.GCP_API_GATEWAY
    GCP_APP_ENGINE_APPLICATION = ASMEntityType.GCP_APP_ENGINE_APPLICATION
    GCP_CLOUD_FUNCTION = ASMEntityType.GCP_CLOUD_FUNCTION
    GCP_CLOUD_SQL_INSTANCE = ASMEntityType.GCP_CLOUD_SQL_INSTANCE
    GCP_COMPUTE_ENGINE_INSTANCE = ASMEntityType.GCP_COMPUTE_ENGINE_INSTANCE
    GCP_STORAGE_BUCKET = ASMEntityType.GCP_STORAGE_BUCKET
    GITHUB_ACCOUNT = ASMEntityType.GITHUB_ACCOUNT
    GITHUB_REPOSITORY = ASMEntityType.GITHUB_REPOSITORY
    IP_ADDRESS = ASMEntityType.IP_ADDRESS
    NAMESERVER = ASMEntityType.NAMESERVER
    NET_BLOCK = ASMEntityType.NET_BLOCK
    NETWORK_SERVICE = ASMEntityType.NETWORK_SERVICE
    SSL_CERTIFICATE = ASMEntityType.SSL_CERTIFICATE
    UNIQUE_KEYWORD = ASMEntityType.UNIQUE_KEYWORD
    UNIQUE_TOKEN = ASMEntityType.UNIQUE_TOKEN
    URI = ASMEntityType.URI


# =============================================================================
# DTM Alert Response
# =============================================================================


class DTMAlertResponse:
    """Response wrapper for DTM alerts that includes pagination info.

    The DTM API returns alerts in an "alerts" array and uses Link headers
    for pagination.

    Attributes:
        alerts: List of alert objects.
        next_page: Next page token extracted from Link header.
        has_next: Whether there are more results.
        raw_response: The raw API response.
        headers: Response headers.

    Example:
        >>> response = client.dtm_alerts.list()
        >>> for alert in response.alerts:
        ...     print(alert["id"], alert["title"])
        ...
        >>> if response.has_next:
        ...     next_response = client.dtm_alerts.list(page=response.next_page)
    """

    def __init__(
        self,
        alerts: List[Dict[str, Any]],
        next_page: Optional[str],
        raw_response: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ):
        self.alerts = alerts
        self.next_page = next_page
        self.has_next = next_page is not None
        self.raw_response = raw_response
        self.headers = headers or {}

    @property
    def data(self) -> List[Dict[str, Any]]:
        """Alias for alerts property for consistency."""
        return self.alerts

    def __iter__(self):
        """Allow iteration over alerts."""
        return iter(self.alerts)

    def __len__(self):
        """Return number of alerts."""
        return len(self.alerts)

    def __getitem__(self, key):
        """Allow dict-like access to raw response."""
        return self.raw_response[key]

    def get(self, key, default=None):
        """Allow dict-like get access to raw response."""
        return self.raw_response.get(key, default)

    def keys(self):
        """Return keys of raw response."""
        return self.raw_response.keys()

    def items(self):
        """Return items of raw response."""
        return self.raw_response.items()

    def values(self):
        """Return values of raw response."""
        return self.raw_response.values()

    @classmethod
    def from_response(
        cls,
        json_data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> "DTMAlertResponse":
        """Create DTMAlertResponse from API response.

        The DTM API returns alerts in an "alerts" key.

        Args:
            json_data: Parsed JSON response.
            headers: Response headers.

        Returns:
            DTMAlertResponse instance.
        """
        # DTM API uses "alerts" key, not "data"
        alerts = json_data.get("alerts", [])
        next_page = cls._extract_next_page(headers)

        return cls(
            alerts=alerts,
            next_page=next_page,
            raw_response=json_data,
            headers=headers,
        )

    @staticmethod
    def _extract_next_page(headers: Optional[Dict[str, str]]) -> Optional[str]:
        """Extract next page token from Link header.

        The Link header format is:
        <https://www.virustotal.com/api/v3/dtm/alerts?page=TOKEN>; rel="next"

        Args:
            headers: Response headers dict.

        Returns:
            Next page token or None.
        """
        if not headers:
            return None

        # Headers can be case-insensitive
        link_header = headers.get("Link") or headers.get("link")
        if not link_header:
            return None

        # Parse Link header: <URL>; rel="next"
        # Pattern to extract page parameter from URL with rel="next"
        pattern = r'<[^>]*[?&]page=([^>&]+)[^>]*>;\s*rel=["\']?next["\']?'
        match = re.search(pattern, link_header, re.IGNORECASE)

        if match:
            return match.group(1)

        return None


# =============================================================================
# DTM Alerts
# =============================================================================


class DTMAlerts:
    """Digital Threat Monitoring (DTM) Alerts handler.

    Provides access to DTM alerts for the current organization.

    DTM alerts notify you about potential threats discovered across:
        - Compromised credentials
        - Domain discoveries
        - Forum posts
        - Messages
        - Pastes
        - Shop listings
        - Tweets
        - Web content

    Response Format:
        The API returns alerts in an "alerts" array with fields including:
        - id: Unique alert identifier
        - monitor_id: ID of the monitor that triggered the alert
        - doc: The document/content that triggered the alert
        - labels: Classification labels
        - topics: Extracted topics/entities
        - status: Alert status (new, read, closed, etc.)
        - alert_type: Type of alert (e.g., "Compromised Credentials")
        - severity: Alert severity (high, medium, low)
        - title: Alert title
        - created_at/updated_at: Timestamps
        - tags: User-defined tags

    Pagination:
        The API uses Link headers for pagination. When fetching subsequent pages,
        only the page parameter should be used (no other query parameters).

    Example:
        >>> with Client(apikey="your_api_key") as client:
        ...     try:
        ...         # List alerts
        ...         response = client.dtm_alerts.list(size=20)
        ...         for alert in response.alerts:
        ...             print(f"{alert['id']}: {alert['title']}")
        ...
        ...         # Get next page if available
        ...         if response.has_next:
        ...             next_response = client.dtm_alerts.list(page=response.next_page)
        ...     except DTMAlertError as e:
        ...         print(f"DTM error: {e}")
        ...     except ResourceNotFoundError as e:
        ...         print(f"Alert not found: {e}")
    """

    # Regex pattern to extract page token from Link header
    _LINK_HEADER_PATTERN = re.compile(
        r'<[^>]*[?&]page=([^>&]+)[^>]*>;\s*rel=["\']?next["\']?', re.IGNORECASE
    )

    # Valid values for validation
    _VALID_SORT_FIELDS = [e.value for e in AlertSortField]
    _VALID_SORT_ORDERS = [e.value for e in AlertSortOrder]
    _VALID_STATUSES = [e.value for e in AlertStatus]
    _VALID_ALERT_TYPES = [e.value for e in AlertType]
    _VALID_SEVERITIES = [e.value for e in AlertSeverity]

    def __init__(self, client: "Client"):
        """Initialize the DTM Alerts endpoint.

        Args:
            client: GTI Client instance.
        """
        self._client = client

    def _validate_size(self, size: int) -> None:
        """Validate the size parameter.

        Args:
            size: Size value to validate.

        Raises:
            InvalidLimitError: If size is out of valid range.
        """
        if size < 1:
            raise InvalidLimitError(
                message=f"size must be at least 1, got {size}",
                value=size,
                min_limit=1,
                max_limit=MAX_DTM_ALERTS_PAGE_SIZE,
            )
        if size > MAX_DTM_ALERTS_PAGE_SIZE:
            raise InvalidLimitError(
                message=f"size cannot exceed {MAX_DTM_ALERTS_PAGE_SIZE}, got {size}",
                value=size,
                min_limit=1,
                max_limit=MAX_DTM_ALERTS_PAGE_SIZE,
            )

    def _validate_mscore(self, mscore_gte: int) -> None:
        """Validate mscore_gte parameter.

        Args:
            mscore_gte: Score value to validate.

        Raises:
            InvalidParameterError: If mscore is out of valid range.
        """
        if mscore_gte < 0 or mscore_gte > 100:
            raise InvalidParameterError(
                message=f"mscore_gte must be between 0 and 100, got {mscore_gte}",
                parameter="mscore_gte",
                value=mscore_gte,
                expected="Integer between 0 and 100",
            )

    def _validate_alert_id(self, alert_id: str) -> None:
        """Validate alert ID parameter.

        Args:
            alert_id: Alert ID to validate.

        Raises:
            InvalidParameterError: If alert_id is empty or invalid.
        """
        if not alert_id:
            raise InvalidParameterError(
                message="Alert ID cannot be empty",
                parameter="alert_id",
                value=alert_id,
                expected="Non-empty string",
            )
        if not isinstance(alert_id, str):
            raise InvalidParameterError(
                message="Alert ID must be a string",
                parameter="alert_id",
                value=type(alert_id).__name__,
                expected="String",
            )

    def _validate_tags(self, tags: List[str]) -> None:
        """Validate tags parameter.

        Args:
            tags: Tags list to validate.

        Raises:
            InvalidParameterError: If tags are invalid.
        """
        if not isinstance(tags, list):
            raise InvalidParameterError(
                message="Tags must be a list",
                parameter="tags",
                value=type(tags).__name__,
                expected="List of strings",
            )
        for tag in tags:
            if not isinstance(tag, str):
                raise InvalidParameterError(
                    message="Each tag must be a string",
                    parameter="tags",
                    value=type(tag).__name__,
                    expected="String",
                )
            if not tag.strip():
                raise InvalidParameterError(
                    message="Tags cannot be empty strings",
                    parameter="tags",
                    value=tag,
                    expected="Non-empty string",
                )

    def _normalize_enum_value(self, value: Union[enum.Enum, str]) -> str:
        """Convert enum to string value.

        Args:
            value: Enum or string value.

        Returns:
            String value.
        """
        if isinstance(value, enum.Enum):
            return value.value
        return value

    def _normalize_enum_list(
        self, values: Optional[Union[List[enum.Enum], List[str]]]
    ) -> Optional[List[str]]:
        """Convert list of enums to list of string values.

        Args:
            values: List of enum or string values.

        Returns:
            List of string values or None.
        """
        if values is None:
            return None
        return [self._normalize_enum_value(v) for v in values]

    def _extract_next_page_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract next page token from Link header.

        Link header format:
        <https://www.virustotal.com/api/v3/dtm/alerts?page=TOKEN>; rel="next"

        Args:
            headers: Response headers.

        Returns:
            Next page token or None if not found.
        """
        # Headers can be case-insensitive
        link_header = headers.get("Link") or headers.get("link")
        if not link_header:
            return None

        match = self._LINK_HEADER_PATTERN.search(link_header)
        if match:
            return match.group(1)

        return None

    def _handle_dtm_api_error(
        self,
        error: APIError,
        alert_id: Optional[str] = None,
        action: str = "retrieve",
    ) -> None:
        """Handle API errors for DTM operations.

        Args:
            error: The APIError that occurred.
            alert_id: Alert ID if applicable.
            action: Action being performed (for error messages).

        Raises:
            ResourceNotFoundError: If alert was not found.
            DTMAlertError: For other DTM-specific errors.
            APIError: For general API errors.
        """
        if error.http_status == 404:
            if alert_id:
                raise ResourceNotFoundError(
                    code="NotFoundError",
                    message=f"DTM alert not found: {alert_id}",
                    http_status=404,
                    resource_type="dtm_alert",
                    resource_id=alert_id,
                ) from error
            raise ResourceNotFoundError(
                code="NotFoundError",
                message=f"Resource not found: {error.message}",
                http_status=404,
            ) from error
        elif error.http_status == 400:
            raise DTMAlertError(
                f"Invalid request while trying to {action} DTM alert: {error.message}"
            ) from error
        elif error.http_status == 403:
            raise DTMAlertError(
                f"Permission denied while trying to {action} DTM alert: {error.message}"
            ) from error
        elif error.http_status and error.http_status >= 500:
            raise DTMAlertError(
                f"Server error while trying to {action} DTM alert: {error.message}"
            ) from error
        else:
            raise DTMAlertError(
                f"Failed to {action} DTM alert: {error.message}"
            ) from error

    def list(
        self,
        sort: Union[AlertSortField, str] = AlertSortField.CREATED_AT,
        order: Union[AlertSortOrder, str] = AlertSortOrder.DESC,
        size: int = DEFAULT_ALERTS_PAGE_SIZE,
        monitor_id: Optional[Union[str, List[str]]] = None,
        refs: bool = True,
        replace_links: bool = False,
        monitor_name: bool = False,
        has_analysis: Optional[bool] = None,
        buckets: bool = False,
        since: Optional[str] = None,
        until: Optional[str] = None,
        page: Optional[str] = None,
        truncate: Optional[int] = None,
        status: Optional[Union[List[AlertStatus], List[str]]] = None,
        alert_type: Optional[Union[List[AlertType], List[str]]] = None,
        search: Optional[str] = None,
        match_value: Optional[Union[str, List[str]]] = None,
        tags: Optional[Union[str, List[str]]] = None,
        search_encoding: Optional[str] = None,
        severity: Optional[Union[List[AlertSeverity], List[str]]] = None,
        sanitize: Optional[Union[bool, str]] = None,
        mscore_gte: Optional[int] = None,
    ) -> DTMAlertResponse:
        """List DTM alerts for the organization.

        Note:
            When using the `page` parameter for pagination, no other query
            parameters can be used. The page token is obtained from the
            `next_page` attribute of the returned `DTMAlertResponse`.

        Args:
            sort: Field to sort by (id, created_at, updated_at, monitor_id).
            order: Sort order (asc, desc).
            size: Number of alerts per page (1-25, default 10).
            monitor_id: Filter by monitor ID(s).
            refs: If False, doc, labels, and topics are not returned.
            replace_links: If True, sanitize and replace links in alert doc.
            monitor_name: If True, include monitor name in response.
            has_analysis: If True, only return alerts with analysis.
            buckets: If True, return alert buckets for aggregated alerts.
            since: Start date in RFC3339 format.
            until: End date in RFC3339 format.
            page: Pagination token (from previous response's next_page).
                  When used, no other parameters are allowed.
            truncate: Truncate document fields to given length.
            status: Filter by status(es).
            alert_type: Filter by alert type(s).
            search: Lucene query string for searching.
            match_value: Filter by match value(s).
            tags: Filter by tag(s).
            search_encoding: Encoding type for search (base64).
            severity: Filter by severity (high, medium, low).
            sanitize: Sanitize HTML content or specify JSON path.
            mscore_gte: Filter alerts with mscores >= value (0-100).

        Returns:
            DTMAlertResponse containing alerts and pagination info.
            Access alerts via response.alerts or iterate directly.

        Raises:
            InvalidLimitError: If size is out of valid range.
            InvalidParameterError: If mscore_gte is invalid.
            DTMAlertError: If retrieval fails.
            APIError: If API request fails.

        Example:
            >>> # Get latest high severity alerts
            >>> response = client.dtm_alerts.list(
            ...     severity=[AlertSeverity.HIGH],
            ...     size=20,
            ... )
            >>> for alert in response.alerts:
            ...     print(f"{alert['title']} - {alert['severity']}")
        """
        try:
            # When using page parameter, no other parameters are allowed
            if page is not None:
                response = self._client.session.get(
                    self._client._build_url(DTMAlertEndpoints.ALERTS),
                    params={"page": page},
                    timeout=self._client._timeout,
                )
                self._client._handle_response(response)

                # Extract headers for pagination
                headers = dict(response.headers)
                json_data = response.json()

                return DTMAlertResponse.from_response(json_data, headers)

            # Validate size
            self._validate_size(size)

            # Validate mscore_gte if provided
            if mscore_gte is not None:
                self._validate_mscore(mscore_gte)

            # Build parameters
            params: Dict[str, Any] = {
                "sort": self._normalize_enum_value(sort),
                "order": self._normalize_enum_value(order),
                "size": size,
                "refs": refs,
                "replace_links": replace_links,
                "monitor_name": monitor_name,
                "buckets": buckets,
            }

            # Handle monitor_id (can be specified multiple times)
            if monitor_id is not None:
                if isinstance(monitor_id, str):
                    params["monitor_id"] = monitor_id
                else:
                    params["monitor_id"] = monitor_id

            if has_analysis is not None:
                params["has_analysis"] = has_analysis

            if since:
                params["since"] = since

            if until:
                params["until"] = until

            if truncate is not None:
                params["truncate"] = truncate

            # Handle status (can be specified multiple times)
            if status:
                params["status"] = self._normalize_enum_list(status)

            # Handle alert_type (can be specified multiple times)
            if alert_type:
                params["alert_type"] = self._normalize_enum_list(alert_type)

            if search:
                params["search"] = search

            if search_encoding:
                params["search_encoding"] = search_encoding

            # Handle match_value (can be specified multiple times)
            if match_value:
                if isinstance(match_value, str):
                    params["match_value"] = match_value
                else:
                    params["match_value"] = match_value

            # Handle tags (can be specified multiple times)
            if tags:
                if isinstance(tags, str):
                    params["tags"] = tags
                else:
                    params["tags"] = tags

            # Handle severity (can be specified multiple times)
            if severity:
                params["severity"] = self._normalize_enum_list(severity)

            if sanitize is not None:
                params["sanitize"] = sanitize

            if mscore_gte is not None:
                params["mscore_gte"] = mscore_gte

            # Make request and capture headers
            response = self._client.session.get(
                self._client._build_url(DTMAlertEndpoints.ALERTS),
                params=params,
                timeout=self._client._timeout,
            )
            self._client._handle_response(response)

            # Extract headers for pagination
            headers = dict(response.headers)
            json_data = response.json()

            return DTMAlertResponse.from_response(json_data, headers)

        except APIError as e:
            self._handle_dtm_api_error(e, action="list")

    def iter(
        self,
        limit: Optional[int] = None,
        sort: Union[AlertSortField, str] = AlertSortField.CREATED_AT,
        order: Union[AlertSortOrder, str] = AlertSortOrder.DESC,
        batch_size: int = MAX_DTM_ALERTS_PAGE_SIZE,
        monitor_id: Optional[Union[str, List[str]]] = None,
        status: Optional[Union[List[AlertStatus], List[str]]] = None,
        alert_type: Optional[Union[List[AlertType], List[str]]] = None,
        severity: Optional[Union[List[AlertSeverity], List[str]]] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        search: Optional[str] = None,
        tags: Optional[Union[str, List[str]]] = None,
        **kwargs,
    ) -> Iterator[Dict[str, Any]]:
        """Iterate through DTM alerts with automatic pagination.

        This method handles pagination automatically using the Link header.
        On subsequent pages, only the page token is used (as per API requirements).

        Args:
            limit: Maximum total alerts to retrieve (None for all).
            sort: Field to sort by.
            order: Sort order.
            batch_size: Alerts per request (max 25).
            monitor_id: Filter by monitor ID(s).
            status: Filter by status(es).
            alert_type: Filter by alert type(s).
            severity: Filter by severity.
            since: Start date in RFC3339 format.
            until: End date in RFC3339 format.
            search: Lucene query string.
            tags: Filter by tag(s).
            **kwargs: Additional parameters passed to list().

        Yields:
            Individual alert objects (dictionaries).

        Raises:
            InvalidLimitError: If batch_size is out of valid range.
            DTMAlertError: If retrieval fails.

        Example:
            >>> # Iterate through all high severity alerts
            >>> for alert in client.dtm_alerts.iter(
            ...     severity=[AlertSeverity.HIGH],
            ...     limit=100
            ... ):
            ...     print(f"{alert['id']}: {alert['title']}")
        """
        # Validate batch_size
        if batch_size < 1:
            raise InvalidLimitError(
                message=f"batch_size must be at least 1, got {batch_size}",
                value=batch_size,
                min_limit=1,
                max_limit=MAX_DTM_ALERTS_PAGE_SIZE,
            )

        retrieved = 0
        batch_size = min(batch_size, MAX_DTM_ALERTS_PAGE_SIZE)
        next_page = None
        is_first_request = True

        while True:
            # Calculate fetch size
            fetch_size = batch_size
            if limit is not None:
                remaining = limit - retrieved
                if remaining <= 0:
                    break
                fetch_size = min(batch_size, remaining)

            # Make request
            if is_first_request:
                # First request: use all parameters
                response = self.list(
                    sort=sort,
                    order=order,
                    size=fetch_size,
                    monitor_id=monitor_id,
                    status=status,
                    alert_type=alert_type,
                    severity=severity,
                    since=since,
                    until=until,
                    search=search,
                    tags=tags,
                    **kwargs,
                )
                is_first_request = False
            else:
                # Subsequent requests: only use page parameter
                response = self.list(page=next_page)

            # Process alerts
            alerts = response.alerts
            if not alerts:
                break

            for alert in alerts:
                yield alert
                retrieved += 1
                if limit is not None and retrieved >= limit:
                    return

            # Check for next page
            if not response.has_next:
                break

            next_page = response.next_page

    def get(self, alert_id: str) -> Dict[str, Any]:
        """Get a specific alert by ID.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with alert data.

        Raises:
            InvalidParameterError: If alert_id is empty or invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If retrieval fails.

        Example:
            >>> try:
            ...     alert = client.dtm_alerts.get("d61u6dfi95os73c7258g")
            ...     print(alert["title"])
            ... except ResourceNotFoundError:
            ...     print("Alert not found")
        """
        self._validate_alert_id(alert_id)

        try:
            return self._client.get_json(DTMAlertEndpoints.ALERT, alert_id)
        except APIError as e:
            self._handle_dtm_api_error(e, alert_id=alert_id, action="retrieve")

    def update(
        self,
        alert_id: str,
        status: Optional[Union[AlertStatus, str]] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Update field(s) of an alert.

        Args:
            alert_id: The alert ID.
            status: New status for the alert.
            tags: Tags to set on the alert.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid or neither status nor tags provided.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> try:
            ...     client.dtm_alerts.update(
            ...         "alert_id",
            ...         status=AlertStatus.CLOSED
            ...     )
            ... except ResourceNotFoundError:
            ...     print("Alert not found")
        """
        self._validate_alert_id(alert_id)

        if status is None and tags is None:
            raise InvalidParameterError(
                message="At least one of 'status' or 'tags' must be provided",
                parameter="status/tags",
                value=None,
                expected="status or tags parameter",
            )

        data: Dict[str, Any] = {}

        if status is not None:
            data["status"] = self._normalize_enum_value(status)

        if tags is not None:
            self._validate_tags(tags)
            data["tags"] = tags

        try:
            return self._client.patch(
                DTMAlertEndpoints.ALERT,
                alert_id,
                json_data=data,
            ).json()
        except APIError as e:
            self._handle_dtm_api_error(e, alert_id=alert_id, action="update")

    def close(self, alert_id: str) -> Dict[str, Any]:
        """Close an alert.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.close("alert_id")
        """
        return self.update(alert_id, status=AlertStatus.CLOSED)

    def mark_as_read(self, alert_id: str) -> Dict[str, Any]:
        """Mark an alert as read.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.mark_as_read("alert_id")
        """
        return self.update(alert_id, status=AlertStatus.READ)

    def escalate(self, alert_id: str) -> Dict[str, Any]:
        """Escalate an alert.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.escalate("alert_id")
        """
        return self.update(alert_id, status=AlertStatus.ESCALATED)

    def mark_in_progress(self, alert_id: str) -> Dict[str, Any]:
        """Mark an alert as in progress.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.mark_in_progress("alert_id")
        """
        return self.update(alert_id, status=AlertStatus.IN_PROGRESS)

    def mark_not_relevant(self, alert_id: str) -> Dict[str, Any]:
        """Mark an alert as not relevant.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.mark_not_relevant("alert_id")
        """
        return self.update(alert_id, status=AlertStatus.NOT_RELEVANT)

    def mark_duplicate(self, alert_id: str) -> Dict[str, Any]:
        """Mark an alert as duplicate.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.mark_duplicate("alert_id")
        """
        return self.update(alert_id, status=AlertStatus.DUPLICATE)

    def mark_no_action_required(self, alert_id: str) -> Dict[str, Any]:
        """Mark an alert as no action required.

        Args:
            alert_id: The alert ID.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id is invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.mark_no_action_required("alert_id")
        """
        return self.update(alert_id, status=AlertStatus.NO_ACTION_REQUIRED)

    def add_tags(
        self,
        alert_id: str,
        tags: List[str],
    ) -> Dict[str, Any]:
        """Set tags on an alert.

        Note: This replaces all existing tags with the provided list.

        Args:
            alert_id: The alert ID.
            tags: Tags to set.

        Returns:
            API response with updated alert data.

        Raises:
            InvalidParameterError: If alert_id or tags are invalid.
            ResourceNotFoundError: If alert is not found.
            DTMAlertError: If update fails.

        Example:
            >>> client.dtm_alerts.add_tags("alert_id", ["tag1", "tag2"])
        """
        return self.update(alert_id, tags=tags)


# =============================================================================
# ASM Alerts (Issues)
# =============================================================================


class ASMAlerts:
    """Attack Surface Management (ASM) Alerts/Issues handler.

    Provides access to ASM issues (security vulnerabilities and misconfigurations)
    discovered across your organization's attack surface.

    ASM issues cover various entity types:
        - Cloud resources (AWS, Azure, GCP)
        - Network infrastructure (IPs, domains, DNS)
        - Code repositories (GitHub)
        - SSL certificates
        - And more

    Example:
        >>> with Client(apikey="your_api_key") as client:
        ...     try:
        ...         # List projects
        ...         projects = client.asm_alerts.list_projects()
        ...
        ...         # Search high severity issues
        ...         issues = client.asm_alerts.search("severity:5")
        ...     except ASMAlertError as e:
        ...         print(f"ASM error: {e}")
        ...     except ResourceNotFoundError as e:
        ...         print(f"Resource not found: {e}")
    """

    # Valid severity range
    _MIN_SEVERITY = 1
    _MAX_SEVERITY = 5

    def __init__(self, client: "Client"):
        """Initialize the ASM Alerts endpoint.

        Args:
            client: GTI Client instance.
        """
        self._client = client

    def _validate_page_size(self, page_size: int) -> None:
        """Validate the page_size parameter.

        Args:
            page_size: Page size to validate.

        Raises:
            InvalidLimitError: If page_size is out of valid range.
        """
        if page_size < 1:
            raise InvalidLimitError(
                message=f"page_size must be at least 1, got {page_size}",
                value=page_size,
                min_limit=1,
                max_limit=MAX_ASM_ALERTS_PAGE_SIZE,
            )
        if page_size > MAX_ASM_ALERTS_PAGE_SIZE:
            raise InvalidLimitError(
                message=f"page_size cannot exceed {MAX_ASM_ALERTS_PAGE_SIZE}, got {page_size}",
                value=page_size,
                min_limit=1,
                max_limit=MAX_ASM_ALERTS_PAGE_SIZE,
            )

    def _validate_severity(self, severity: int) -> None:
        """Validate severity value.

        Args:
            severity: Severity value to validate.

        Raises:
            InvalidParameterError: If severity is out of valid range.
        """
        if severity < self._MIN_SEVERITY or severity > self._MAX_SEVERITY:
            raise InvalidParameterError(
                message=f"severity must be between {self._MIN_SEVERITY} and {self._MAX_SEVERITY}, got {severity}",
                parameter="severity",
                value=severity,
                expected=f"Integer between {self._MIN_SEVERITY} and {self._MAX_SEVERITY}",
            )

    def _validate_search_string(self, search_string: str) -> None:
        """Validate search string.

        Args:
            search_string: Search string to validate.

        Raises:
            InvalidParameterError: If search string is empty or invalid.
        """
        if not search_string:
            raise InvalidParameterError(
                message="Search string cannot be empty",
                parameter="search_string",
                value=search_string,
                expected="Non-empty string",
            )
        if not isinstance(search_string, str):
            raise InvalidParameterError(
                message="Search string must be a string",
                parameter="search_string",
                value=type(search_string).__name__,
                expected="String",
            )

    def _validate_project_id(self, project_id: str) -> None:
        """Validate project ID.

        Args:
            project_id: Project ID to validate.

        Raises:
            InvalidParameterError: If project_id is empty or invalid.
        """
        if not project_id:
            raise InvalidParameterError(
                message="Project ID cannot be empty",
                parameter="project_id",
                value=project_id,
                expected="Non-empty string",
            )
        if not isinstance(project_id, str):
            raise InvalidParameterError(
                message="Project ID must be a string",
                parameter="project_id",
                value=type(project_id).__name__,
                expected="String",
            )

    def _handle_asm_api_error(
        self,
        error: APIError,
        resource_id: Optional[str] = None,
        resource_type: str = "resource",
        action: str = "retrieve",
    ) -> None:
        """Handle API errors for ASM operations.

        Args:
            error: The APIError that occurred.
            resource_id: Resource ID if applicable.
            resource_type: Type of resource (for error messages).
            action: Action being performed (for error messages).

        Raises:
            ResourceNotFoundError: If resource was not found.
            ASMAlertError: For other ASM-specific errors.
            APIError: For general API errors.
        """
        if error.http_status == 404:
            if resource_id:
                raise ResourceNotFoundError(
                    code="NotFoundError",
                    message=f"ASM {resource_type} not found: {resource_id}",
                    http_status=404,
                    resource_type=f"asm_{resource_type}",
                    resource_id=resource_id,
                ) from error
            raise ResourceNotFoundError(
                code="NotFoundError",
                message=f"ASM {resource_type} not found: {error.message}",
                http_status=404,
            ) from error
        elif error.http_status == 400:
            raise ASMAlertError(
                f"Invalid request while trying to {action} ASM {resource_type}: {error.message}"
            ) from error
        elif error.http_status == 403:
            raise ASMAlertError(
                f"Permission denied while trying to {action} ASM {resource_type}: {error.message}"
            ) from error
        elif error.http_status and error.http_status >= 500:
            raise ASMAlertError(
                f"Server error while trying to {action} ASM {resource_type}: {error.message}"
            ) from error
        else:
            raise ASMAlertError(
                f"Failed to {action} ASM {resource_type}: {error.message}"
            ) from error

    def list_projects(self) -> Dict[str, Any]:
        """List all ASM projects.

        Returns:
            API response with projects data.

        Raises:
            ASMAlertError: If retrieval fails.
            APIError: If API request fails.

        Example:
            >>> try:
            ...     projects = client.asm_alerts.list_projects()
            ...     for project in projects["result"]:
            ...         print(f"{project['name']}: {project['uuid']}")
            ... except ASMAlertError as e:
            ...     print(f"Failed to list projects: {e}")
        """
        try:
            return self._client.get_json(ASMEndpoints.PROJECTS)
        except APIError as e:
            self._handle_asm_api_error(e, resource_type="projects", action="list")

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific project by ID or UUID.

        Args:
            project_id: Project ID or UUID.

        Returns:
            Project data if found, None otherwise.

        Raises:
            InvalidParameterError: If project_id is empty or invalid.
            ASMAlertError: If retrieval fails.

        Example:
            >>> try:
            ...     project = client.asm_alerts.get_project("project_uuid")
            ...     if project:
            ...         print(project["name"])
            ...     else:
            ...         print("Project not found")
            ... except ASMAlertError as e:
            ...     print(f"Error: {e}")
        """
        self._validate_project_id(project_id)

        try:
            response = self.list_projects()
            projects = response.get("result", [])

            for project in projects:
                if (
                    str(project.get("id")) == project_id
                    or project.get("uuid") == project_id
                ):
                    return project

            return None
        except ASMAlertError:
            raise
        except APIError as e:
            self._handle_asm_api_error(
                e,
                resource_id=project_id,
                resource_type="project",
                action="retrieve",
            )

    def get_primary_project(self) -> Optional[Dict[str, Any]]:
        """Get the primary ASM project.

        Returns:
            Primary project data if found, None otherwise.

        Raises:
            ASMAlertError: If retrieval fails.

        Example:
            >>> try:
            ...     project = client.asm_alerts.get_primary_project()
            ...     if project:
            ...         print(f"Primary project: {project['name']}")
            ...     else:
            ...         print("No primary project found")
            ... except ASMAlertError as e:
            ...     print(f"Error: {e}")
        """
        try:
            response = self.list_projects()
            projects = response.get("result", [])

            for project in projects:
                if project.get("primary", False):
                    return project

            return None
        except ASMAlertError:
            raise
        except APIError as e:
            self._handle_asm_api_error(e, resource_type="primary project", action="retrieve")

    def search(
        self,
        search_string: str,
        page_size: int = DEFAULT_ASM_PAGE_SIZE,
        page_token: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search ASM issues.

        Valid search keywords:
            - collection:name_123k221
            - name:string
            - uid:12345
            - tag:tag_name
            - last_seen_after:YYYY-MM-DD
            - last_seen_before:YYYY-MM-DD
            - first_seen_after:YYYY-MM-DD
            - entity_uid:12345
            - entity_type:Domain (see EntityType enum)
            - entity_name:string
            - scoped:true|false
            - severity:1-5
            - severity_lte:1-5
            - severity_gte:1-5
            - status_new:open|closed
            - status_detailed:open_triaged|closed_resolved|... (see IssueStatus)

        Args:
            search_string: Search query string with keywords.
            page_size: Results per page (1-100, default 50).
            page_token: Token for pagination (from previous response).
            project_id: Optional project ID/UUID to filter by.

        Returns:
            API response with search results.

        Raises:
            InvalidParameterError: If search_string or project_id is invalid.
            InvalidLimitError: If page_size is out of range.
            ASMAlertError: If search fails.

        Example:
            >>> try:
            ...     # Search high severity issues
            ...     results = client.asm_alerts.search("severity:5")
            ...
            ...     # Complex search
            ...     results = client.asm_alerts.search(
            ...         "severity_gte:4 status_new:open entity_type:IpAddress"
            ...     )
            ... except ASMAlertError as e:
            ...     print(f"Search failed: {e}")
        """
        self._validate_search_string(search_string)
        self._validate_page_size(page_size)

        if project_id is not None:
            self._validate_project_id(project_id)

        params: Dict[str, Any] = {"page_size": page_size}

        if page_token:
            params["page_token"] = page_token

        # Build endpoint URL with search string
        endpoint = ASMEndpoints.SEARCH_ISSUES.format(search_string)

        try:
            # Add project ID header if provided
            if project_id:
                response = self._client.session.get(
                    self._client._build_url(endpoint),
                    params=params,
                    headers={"PROJECT-ID": project_id},
                    timeout=self._client._timeout,
                )
                return self._client._handle_response(response).json()
            else:
                return self._client.get_json(endpoint, params=params)
        except APIError as e:
            self._handle_asm_api_error(e, resource_type="issues", action="search")

    def iter_search(
        self,
        search_string: str,
        limit: Optional[int] = None,
        page_size: int = DEFAULT_ASM_PAGE_SIZE,
        project_id: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Iterate through ASM issues with automatic pagination.

        Args:
            search_string: Search query string.
            limit: Maximum total issues to retrieve (None for all).
            page_size: Results per page (max 100).
            project_id: Optional project ID/UUID to filter by.

        Yields:
            Individual issue objects.

        Raises:
            InvalidParameterError: If search_string is invalid.
            InvalidLimitError: If page_size is out of range.
            ASMAlertError: If search fails.

        Example:
            >>> try:
            ...     # Iterate through all critical issues
            ...     for issue in client.asm_alerts.iter_search(
            ...         "severity:5",
            ...         limit=100
            ...     ):
            ...         print(f"{issue['name']}: {issue['entity_name']}")
            ... except ASMAlertError as e:
            ...     print(f"Search failed: {e}")
        """
        # Validate inputs
        self._validate_search_string(search_string)

        if page_size < 1:
            raise InvalidLimitError(
                message=f"page_size must be at least 1, got {page_size}",
                value=page_size,
                min_limit=1,
                max_limit=MAX_ASM_ALERTS_PAGE_SIZE,
            )

        if project_id is not None:
            self._validate_project_id(project_id)

        page_token = None
        retrieved = 0
        page_size = min(page_size, MAX_ASM_ALERTS_PAGE_SIZE)

        while True:
            # Adjust page size if limit is set
            current_page_size = page_size
            if limit is not None:
                remaining = limit - retrieved
                if remaining <= 0:
                    break
                current_page_size = min(page_size, remaining)

            response = self.search(
                search_string=search_string,
                page_size=current_page_size,
                page_token=page_token,
                project_id=project_id,
            )

            result = response.get("result", {})
            hits = result.get("hits", [])

            if not hits:
                break

            for issue in hits:
                yield issue
                retrieved += 1
                if limit is not None and retrieved >= limit:
                    return

            # Check if more results available
            if not result.get("more", False):
                break

            page_token = result.get("next_page_token")
            if not page_token:
                break

    def get_issue(self, issue_id: str, project_id: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific ASM issue by ID.

        Args:
            issue_id: The issue ID/UID.
            project_id: Optional project ID/UUID.

        Returns:
            Issue data.

        Raises:
            InvalidParameterError: If issue_id is invalid.
            ResourceNotFoundError: If issue is not found.
            ASMAlertError: If retrieval fails.

        Example:
            >>> try:
            ...     issue = client.asm_alerts.get_issue("12345")
            ...     print(issue["name"])
            ... except ResourceNotFoundError:
            ...     print("Issue not found")
        """
        if not issue_id:
            raise InvalidParameterError(
                message="Issue ID cannot be empty",
                parameter="issue_id",
                value=issue_id,
                expected="Non-empty string",
            )

        if project_id is not None:
            self._validate_project_id(project_id)

        # Search for the specific issue by UID
        search_string = f"uid:{issue_id}"

        try:
            response = self.search(
                search_string=search_string,
                page_size=1,
                project_id=project_id,
            )

            result = response.get("result", {})
            hits = result.get("hits", [])

            if not hits:
                raise ResourceNotFoundError(
                    code="NotFoundError",
                    message=f"ASM issue not found: {issue_id}",
                    http_status=404,
                    resource_type="asm_issue",
                    resource_id=issue_id,
                )

            return hits[0]
        except ResourceNotFoundError:
            raise
        except ASMAlertError:
            raise
        except APIError as e:
            self._handle_asm_api_error(
                e,
                resource_id=issue_id,
                resource_type="issue",
                action="retrieve",
            )

    def get_issues_by_severity(
        self,
        severity: int,
        limit: Optional[int] = None,
        project_id: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get ASM issues filtered by severity.

        Args:
            severity: Severity level (1-5, where 5 is critical).
            limit: Maximum total issues to retrieve (None for all).
            project_id: Optional project ID/UUID.

        Yields:
            Individual issue objects.

        Raises:
            InvalidParameterError: If severity is invalid.
            ASMAlertError: If search fails.

        Example:
            >>> # Get all critical issues (severity 5)
            >>> for issue in client.asm_alerts.get_issues_by_severity(5, limit=100):
            ...     print(issue["name"])
        """
        self._validate_severity(severity)

        yield from self.iter_search(
            search_string=f"severity:{severity}",
            limit=limit,
            project_id=project_id,
        )

    def get_open_issues(
        self,
        limit: Optional[int] = None,
        project_id: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get all open ASM issues.

        Args:
            limit: Maximum total issues to retrieve (None for all).
            project_id: Optional project ID/UUID.

        Yields:
            Individual issue objects.

        Raises:
            ASMAlertError: If search fails.

        Example:
            >>> for issue in client.asm_alerts.get_open_issues(limit=50):
            ...     print(f"{issue['name']}: severity {issue.get('severity', 'N/A')}")
        """
        yield from self.iter_search(
            search_string="status_new:open",
            limit=limit,
            project_id=project_id,
        )

    def get_critical_open_issues(
        self,
        min_severity: int = 4,
        limit: Optional[int] = None,
        project_id: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get critical open ASM issues (high severity).

        Args:
            min_severity: Minimum severity level (1-5, default 4).
            limit: Maximum total issues to retrieve (None for all).
            project_id: Optional project ID/UUID.

        Yields:
            Individual issue objects.

        Raises:
            InvalidParameterError: If min_severity is invalid.
            ASMAlertError: If search fails.

        Example:
            >>> # Get all critical and high severity open issues
            >>> for issue in client.asm_alerts.get_critical_open_issues(min_severity=4):
            ...     print(f"CRITICAL: {issue['name']}")
        """
        self._validate_severity(min_severity)

        yield from self.iter_search(
            search_string=f"severity_gte:{min_severity} status_new:open",
            limit=limit,
            project_id=project_id,
        )

    def get_issues_by_entity_type(
        self,
        entity_type: Union[EntityType, str],
        limit: Optional[int] = None,
        project_id: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get ASM issues filtered by entity type.

        Args:
            entity_type: Entity type to filter by (EntityType enum or string).
            limit: Maximum total issues to retrieve (None for all).
            project_id: Optional project ID/UUID.

        Yields:
            Individual issue objects.

        Raises:
            ASMAlertError: If search fails.

        Example:
            >>> # Get all domain-related issues
            >>> for issue in client.asm_alerts.get_issues_by_entity_type(
            ...     EntityType.DOMAIN,
            ...     limit=100
            ... ):
            ...     print(issue["entity_name"])
        """
        if isinstance(entity_type, EntityType):
            entity_type_str = entity_type.value
        else:
            entity_type_str = entity_type

        yield from self.iter_search(
            search_string=f"entity_type:{entity_type_str}",
            limit=limit,
            project_id=project_id,
        )
        