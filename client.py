"""GTI API Client - Synchronous implementation."""

import requests
import urllib3
from typing import Any, Dict, Optional, Union

from .exceptions import (
    APIError,
    InvalidAPIKeyError,
    MissingAPIKeyError,
)
from .gti import (
    IOCStream,
    ThreatList,
    URLScan,
    FileScan,
    Comments,
    IPAddress,
    Domain,
    File,
    URL,
    DTMAlerts,
    ASMAlerts
)
from .constants import API_HOST, ENDPOINT_PREFIX, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Client:
    """Google Threat Intelligence (GTI) API Client.

    Args:
        apikey: Your GTI API key.
        agent: A string that identifies your application.
        host: API host URL (default: https://www.virustotal.com).
        timeout: Request timeout in seconds (default: 300).
        headers: Additional headers to include in requests.
        verify: SSL certificate verification (default: False).

    Raises:
        InvalidAPIKeyError: If API key is not a string.
        MissingAPIKeyError: If API key is empty.

    Example:
        >>> with Client(apikey="your_api_key") as client:
        ...     result = client.get_json("/ip_addresses/{}", "8.8.8.8")
        ...     print(result["data"]["attributes"]["country"])
    """

    def __init__(
        self,
        apikey: str,
        agent: str = DEFAULT_USER_AGENT,
        host: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        headers: Optional[Dict[str, str]] = None,
        verify: Union[bool, str] = False,
    ):
        # Validate API key
        if not isinstance(apikey, str):
            raise InvalidAPIKeyError("API key must be a string")
        if not apikey or not apikey.strip():
            raise MissingAPIKeyError("API key cannot be empty")

        self._host = host or API_HOST
        self._apikey = apikey
        self._agent = agent
        self._timeout = timeout
        self._user_headers = headers or {}
        self._verify = verify
        self._session: Optional[requests.Session] = None

        # Feature instances (lazy initialization)
        self._ioc_stream: Optional["IOCStream"] = None
        self._threat_list: Optional["ThreatList"] = None
        self._url_scan: Optional["URLScan"] = None
        self._file_scan: Optional["FileScan"] = None
        self._comments: Optional["Comments"] = None
        self._domain: Optional["Domain"] = None
        self._file: Optional["File"] = None
        self._url: Optional["URL"] = None
        self._ip_address: Optional["IPAddress"] = None
        self._dtm_alerts: Optional["DTMAlerts"] = None
        self._asm_alerts: Optional["ASMAlerts"] = None

    @property
    def ioc_stream(self) -> "IOCStream":
        """IoC Stream endpoint."""
        if self._ioc_stream is None:
            self._ioc_stream = IOCStream(self)
        return self._ioc_stream

    @property
    def threat_list(self) -> "ThreatList":
        """Threat List endpoint."""
        if self._threat_list is None:
            self._threat_list = ThreatList(self)
        return self._threat_list

    @property
    def scan_url(self) -> "URLScan":
        """URL Scan endpoint."""
        if self._url_scan is None:
            self._url_scan = URLScan(self)
        return self._url_scan

    @property
    def scan_file(self) -> "FileScan":
        """File Scan endpoint."""
        if self._file_scan is None:
            self._file_scan = FileScan(self)
        return self._file_scan

    @property
    def comments(self) -> "Comments":
        """Comments endpoint."""
        if self._comments is None:
            self._comments = Comments(self)
        return self._comments

    @property
    def domain(self) -> "Domain":
        """Domain enrichment endpoint."""
        if self._domain is None:
            self._domain = Domain(self)
        return self._domain

    @property
    def file(self) -> "File":
        """File enrichment endpoint."""
        if self._file is None:
            self._file = File(self)
        return self._file

    @property
    def url(self) -> "URL":
        """URL enrichment endpoint."""
        if self._url is None:
            self._url = URL(self)
        return self._url

    @property
    def ip_address(self) -> "IPAddress":
        """IP Address enrichment endpoint."""
        if self._ip_address is None:
            self._ip_address = IPAddress(self)
        return self._ip_address

    @property
    def dtm_alerts(self) -> "DTMAlerts":
        """DTM Alerts endpoint."""
        if self._dtm_alerts is None:
            self._dtm_alerts = DTMAlerts(self)
        return self._dtm_alerts

    @property
    def asm_alerts(self) -> "ASMAlerts":
        """ASM Alerts endpoint."""
        if self._asm_alerts is None:
            self._asm_alerts = ASMAlerts(self)
        return self._asm_alerts

    @property
    def session(self) -> requests.Session:
        """Get or create the requests session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update(
                {
                    "X-Apikey": self._apikey,
                    "Accept-Encoding": "gzip",
                    "User-Agent": self._agent,
                    **self._user_headers,
                }
            )
            self._session.verify = self._verify
        return self._session

    def _build_url(self, path: str, *args: Any) -> str:
        """Build the full URL from a path template and arguments.

        Args:
            path: URL path template with {} placeholders.
            *args: Arguments to fill placeholders.

        Returns:
            Full URL string.

        Raises:
            InvalidParameterError: If not enough arguments for placeholders.
        """
        from .exceptions import InvalidParameterError

        try:
            path = path.format(*args)
        except IndexError as exc:
            raise InvalidParameterError(
                message="Not enough arguments for path placeholders",
                parameter="path_args",
                value=args,
            ) from exc

        if path.startswith("http"):
            return path
        return f"{self._host}{ENDPOINT_PREFIX}{path}"

    def _handle_response(self, response: requests.Response) -> requests.Response:
        """Check response for errors and raise appropriate exception.

        Args:
            response: requests.Response object.

        Returns:
            The response if successful.

        Raises:
            APIError: If the response indicates an error.
        """
        if response.ok:
            return response

        raise APIError.from_response(response)

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        """Close the client session and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None

        # Reset feature instances
        self._ioc_stream = None
        self._threat_list = None
        self._url_scan = None
        self._file_scan = None
        self._comments = None
        self._domain = None
        self._file = None
        self._url = None
        self._ip_address = None
        self._dtm_alerts = None
        self._asm_alerts = None

    def get(
        self,
        path: str,
        *path_args: Any,
        params: Optional[Dict] = None,
    ) -> requests.Response:
        """Send a GET request.

        Args:
            path: URL path template.
            *path_args: Arguments for path placeholders.
            params: Query parameters.

        Returns:
            Response object.

        Raises:
            APIError: If the request fails.
        """
        response = self.session.get(
            self._build_url(path, *path_args),
            params=params,
            timeout=self._timeout,
        )
        return self._handle_response(response)

    def get_json(
        self,
        path: str,
        *path_args: Any,
        params: Optional[Dict] = None,
    ) -> Dict:
        """Send a GET request and return parsed JSON.

        Args:
            path: URL path template.
            *path_args: Arguments for path placeholders.
            params: Query parameters.

        Returns:
            Parsed JSON response.

        Raises:
            APIError: If the request fails.
        """
        return self.get(path, *path_args, params=params).json()

    def post(
        self,
        path: str,
        *path_args: Any,
        data: Optional[Union[str, bytes, Dict]] = None,
        json_data: Optional[Dict] = None,
        files: Optional[Dict] = None,
    ) -> requests.Response:
        """Send a POST request.

        Args:
            path: URL path template.
            *path_args: Arguments for path placeholders.
            data: Form data or raw body.
            json_data: JSON body data.
            files: Files to upload.

        Returns:
            Response object.

        Raises:
            APIError: If the request fails.
        """
        response = self.session.post(
            self._build_url(path, *path_args),
            data=data,
            json=json_data,
            files=files,
            timeout=self._timeout,
        )
        return self._handle_response(response)

    def post_json(
        self,
        path: str,
        *path_args: Any,
        data: Optional[Union[str, bytes, Dict]] = None,
        json_data: Optional[Dict] = None,
    ) -> Dict:
        """Send a POST request and return parsed JSON.

        Args:
            path: URL path template.
            *path_args: Arguments for path placeholders.
            data: Form data or raw body.
            json_data: JSON body data.

        Returns:
            Parsed JSON response.

        Raises:
            APIError: If the request fails.
        """
        return self.post(path, *path_args, data=data, json_data=json_data).json()

    def patch(
        self,
        path: str,
        *path_args: Any,
        json_data: Optional[Dict] = None,
    ) -> requests.Response:
        """Send a PATCH request.

        Args:
            path: URL path template.
            *path_args: Arguments for path placeholders.
            json_data: JSON body data.

        Returns:
            Response object.

        Raises:
            APIError: If the request fails.
        """
        response = self.session.patch(
            self._build_url(path, *path_args),
            json=json_data,
            timeout=self._timeout,
        )
        return self._handle_response(response)

    def delete(
        self,
        path: str,
        *path_args: Any,
    ) -> requests.Response:
        """Send a DELETE request.

        Args:
            path: URL path template.
            *path_args: Arguments for path placeholders.

        Returns:
            Response object.

        Raises:
            APIError: If the request fails.
        """
        response = self.session.delete(
            self._build_url(path, *path_args),
            timeout=self._timeout,
        )
        return self._handle_response(response)
    