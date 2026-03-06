"""
detector.py
-----------
Initial detection of potential vulnerabilities. Sends payloads and looks for indicators.
Returns PotentialVulnerability objects for further verification.
"""

import asyncio
import aiohttp
import logging
import time
import html
import re
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin

from .payload_engine import PayloadEngine

logger = logging.getLogger(__name__)


def inject_into_url(url: str, param_name: str, payload: str, location: str, path_index: int = None) -> str:
    """
    Inject payload into a URL based on parameter location.
    For query: replace parameter value.
    For path: replace the segment at path_index.
    Returns modified URL.
    """
    parsed = urlparse(url)
    if location == 'query':
        # Handle query parameters
        params = parse_qs(parsed.query, keep_blank_values=True)
        # param_name is the actual query key; we replace its value
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, parsed.fragment))
    elif location == 'path' and path_index is not None:
        # Replace the specific path segment
        segments = parsed.path.split('/')
        if path_index < len(segments):
            segments[path_index] = payload
            new_path = '/'.join(segments)
            return urlunparse((parsed.scheme, parsed.netloc, new_path,
                               parsed.params, parsed.query, parsed.fragment))
    # Fallback: return original url
    return url


@dataclass
class PotentialVulnerability:
    """Represents a potential vulnerability found during initial scan."""
    type: str                # e.g., 'SQL Injection'
    url: str
    parameter: str
    method: str
    payload: str
    confidence: float        # 0.0 to 1.0
    evidence_snippet: str    # e.g., SQL error message or reflected payload
    location: str = 'query'          # where parameter came from
    path_index: Optional[int] = None # for path parameters
    extra: Dict[str, Any] = field(default_factory=dict)


class Detector:
    """
    Base detector class. All specific detectors inherit from this.
    """
    def __init__(self, session: aiohttp.ClientSession, delay: float = 0,
                 payload_count: int = 0, no_time_based: bool = False,
                 request_counter: Optional[Callable] = None):
        self.session = session
        self.delay = delay
        self.payload_count = payload_count
        self.no_time_based = no_time_based
        self.request_counter = request_counter or (lambda: None)

    async def detect(self, param_info: dict, baseline: Optional[str] = None) -> List[PotentialVulnerability]:
        """
        Detect potential vulnerabilities for a given parameter.
        Should be overridden by subclasses.
        Returns a list of PotentialVulnerability objects.
        """
        raise NotImplementedError

    async def _make_request(self, url: str, method: str, param: str, payload: str,
                            form_data: Optional[Dict] = None) -> tuple:
        """Make a request with the payload and return status, body, headers."""
        try:
            if method == 'GET':
                async with self.session.get(url) as resp:
                    self.request_counter()
                    body = await resp.text()
                    return resp.status, body, dict(resp.headers)
            else:
                # POST request
                data = form_data.copy() if form_data else {}
                data[param] = payload
                async with self.session.post(url, data=data) as resp:
                    self.request_counter()
                    body = await resp.text()
                    return resp.status, body, dict(resp.headers)
        except Exception as e:
            logger.debug(f"Request error: {e}")
            return 0, "", {}
        finally:
            if self.delay:
                await asyncio.sleep(self.delay)

    async def _make_request_time(self, url: str, method: str, param: str, payload: str,
                                 form_data: Optional[Dict] = None) -> float:
        """Make a request and return elapsed time."""
        start = time.time()
        await self._make_request(url, method, param, payload, form_data)
        return time.time() - start


class SQLiDetector(Detector):
    async def detect(self, param_info: dict, baseline: Optional[str] = None) -> List[PotentialVulnerability]:
        findings = []
        url = param_info['url']
        param = param_info['name']
        method = param_info['method']
        location = param_info.get('location', 'query')
        path_index = param_info.get('path_index')
        form_data = param_info.get('form_data')

        all_payloads = PayloadEngine.get_payloads('sqli')
        if self.payload_count > 0:
            all_payloads = all_payloads[:self.payload_count]

        for payload in all_payloads:
            if self.no_time_based and ('SLEEP' in payload or 'WAITFOR' in payload):
                continue

            # Time-based detection
            if 'SLEEP' in payload or 'WAITFOR' in payload:
                if method == 'GET':
                    test_url = inject_into_url(url, param, payload, location, path_index)
                    elapsed = await self._make_request_time(test_url, method, param, payload, form_data)
                else:
                    elapsed = await self._make_request_time(url, method, param, payload, form_data)
                if elapsed > 5:  # threshold
                    findings.append(PotentialVulnerability(
                        type='SQL Injection (Time-based)',
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        confidence=0.9,
                        evidence_snippet=f"Response time: {elapsed:.2f}s",
                        location=location,
                        path_index=path_index,
                        extra={'form_data': form_data}
                    ))
            else:
                # Error/boolean-based
                if method == 'GET':
                    test_url = inject_into_url(url, param, payload, location, path_index)
                    status, body, headers = await self._make_request(test_url, method, param, payload, form_data)
                else:
                    status, body, headers = await self._make_request(url, method, param, payload, form_data)

                if self._detect_sql_error(body):
                    findings.append(PotentialVulnerability(
                        type='SQL Injection',
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        confidence=0.8,
                        evidence_snippet=body[:200],
                        location=location,
                        path_index=path_index,
                        extra={'form_data': form_data}
                    ))
                elif baseline and self._significant_difference(baseline, body):
                    findings.append(PotentialVulnerability(
                        type='SQL Injection (Blind)',
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        confidence=0.6,
                        evidence_snippet="Response differs significantly from baseline",
                        location=location,
                        path_index=path_index,
                        extra={'form_data': form_data}
                    ))
        return findings

    def _detect_sql_error(self, body: str) -> bool:
        body_lower = body.lower()
        patterns = [
            "sql syntax", "mysql", "ora-", "postgresql error", "sqlite error",
            "unterminated", "quoted string", "unknown column", "column not found"
        ]
        return any(p in body_lower for p in patterns)

    def _significant_difference(self, baseline: str, response: str) -> bool:
        return abs(len(response) - len(baseline)) > 300


class XSSDetector(Detector):
    async def detect(self, param_info: dict, baseline: Optional[str] = None) -> List[PotentialVulnerability]:
        findings = []
        url = param_info['url']
        param = param_info['name']
        method = param_info['method']
        location = param_info.get('location', 'query')
        path_index = param_info.get('path_index')
        form_data = param_info.get('form_data')

        all_payloads = PayloadEngine.get_payloads('xss')
        if self.payload_count > 0:
            all_payloads = all_payloads[:self.payload_count]

        for payload in all_payloads:
            if method == 'GET':
                test_url = inject_into_url(url, param, payload, location, path_index)
                status, body, headers = await self._make_request(test_url, method, param, payload, form_data)
            else:
                status, body, headers = await self._make_request(url, method, param, payload, form_data)

            if self._detect_xss(payload, body):
                findings.append(PotentialVulnerability(
                    type='Cross-Site Scripting (XSS)',
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    confidence=0.7,
                    evidence_snippet=body[:200],
                    location=location,
                    path_index=path_index,
                    extra={'form_data': form_data}
                ))
        return findings

    def _detect_xss(self, payload: str, response: str) -> bool:
        if payload not in response:
            return False
        # Check if encoded
        if html.escape(payload) in response:
            return False
        # Check for executable context (simple)
        response_lower = response.lower()
        if "<script" in response_lower and "</script>" in response_lower:
            if any(x in response_lower for x in ["alert(", "eval(", "document.cookie"]):
                return True
        if re.search(r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload[:10]), response, re.IGNORECASE):
            return True
        if "javascript:" in response_lower and payload in response:
            return True
        return False


class LfiDetector(Detector):
    async def detect(self, param_info: dict, baseline: Optional[str] = None) -> List[PotentialVulnerability]:
        findings = []
        url = param_info['url']
        param = param_info['name']
        method = param_info['method']
        location = param_info.get('location', 'query')
        path_index = param_info.get('path_index')
        form_data = param_info.get('form_data')

        all_payloads = PayloadEngine.get_payloads('lfi')
        if self.payload_count > 0:
            all_payloads = all_payloads[:self.payload_count]

        for payload in all_payloads:
            if method == 'GET':
                test_url = inject_into_url(url, param, payload, location, path_index)
                status, body, headers = await self._make_request(test_url, method, param, payload, form_data)
            else:
                status, body, headers = await self._make_request(url, method, param, payload, form_data)

            if self._detect_lfi(body):
                findings.append(PotentialVulnerability(
                    type='Local File Inclusion',
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    confidence=0.8,
                    evidence_snippet=body[:200],
                    location=location,
                    path_index=path_index,
                    extra={'form_data': form_data}
                ))
        return findings

    def _detect_lfi(self, body: str) -> bool:
        patterns = ["root:", "daemon:", "bin:", "[boot loader]", "www-data:"]
        return any(p in body for p in patterns)


class SsrfDetector(Detector):
    async def detect(self, param_info: dict, baseline: Optional[str] = None) -> List[PotentialVulnerability]:
        findings = []
        url = param_info['url']
        param = param_info['name']
        method = param_info['method']
        location = param_info.get('location', 'query')
        path_index = param_info.get('path_index')
        form_data = param_info.get('form_data')

        all_payloads = PayloadEngine.get_payloads('ssrf')
        if self.payload_count > 0:
            all_payloads = all_payloads[:self.payload_count]

        for payload in all_payloads:
            if method == 'GET':
                test_url = inject_into_url(url, param, payload, location, path_index)
                status, body, headers = await self._make_request(test_url, method, param, payload, form_data)
            else:
                status, body, headers = await self._make_request(url, method, param, payload, form_data)

            body_lower = body.lower()
            # Connection refused / timeout
            if any(err in body_lower for err in ["connection refused", "failed to connect", "timeout"]):
                findings.append(PotentialVulnerability(
                    type='Server-Side Request Forgery',
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    confidence=0.9,
                    evidence_snippet="Connection error detected",
                    location=location,
                    path_index=path_index,
                    extra={'form_data': form_data}
                ))
            # Cloud metadata
            if "169.254.169.254" in body_lower or "metadata.google" in body_lower:
                findings.append(PotentialVulnerability(
                    type='Server-Side Request Forgery',
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    confidence=0.9,
                    evidence_snippet="Cloud metadata response",
                    location=location,
                    path_index=path_index,
                    extra={'form_data': form_data}
                ))
            # File content
            if "root:" in body or "daemon:" in body:
                findings.append(PotentialVulnerability(
                    type='Server-Side Request Forgery (File Read)',
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    confidence=0.9,
                    evidence_snippet=body[:200],
                    location=location,
                    path_index=path_index,
                    extra={'form_data': form_data}
                ))
        return findings


class CmdInjectDetector(Detector):
    async def detect(self, param_info: dict, baseline: Optional[str] = None) -> List[PotentialVulnerability]:
        findings = []
        url = param_info['url']
        param = param_info['name']
        method = param_info['method']
        location = param_info.get('location', 'query')
        path_index = param_info.get('path_index')
        form_data = param_info.get('form_data')

        all_payloads = PayloadEngine.get_payloads('cmdi')
        if self.payload_count > 0:
            all_payloads = all_payloads[:self.payload_count]

        for payload in all_payloads:
            # Skip time-based if requested
            if self.no_time_based and 'sleep' in payload.lower():
                continue

            if 'sleep' in payload.lower():
                if method == 'GET':
                    test_url = inject_into_url(url, param, payload, location, path_index)
                    elapsed = await self._make_request_time(test_url, method, param, payload, form_data)
                else:
                    elapsed = await self._make_request_time(url, method, param, payload, form_data)
                if elapsed > 5:
                    findings.append(PotentialVulnerability(
                        type='Command Injection (Time-based)',
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        confidence=0.9,
                        evidence_snippet=f"Response time: {elapsed:.2f}s",
                        location=location,
                        path_index=path_index,
                        extra={'form_data': form_data}
                    ))
            else:
                if method == 'GET':
                    test_url = inject_into_url(url, param, payload, location, path_index)
                    status, body, headers = await self._make_request(test_url, method, param, payload, form_data)
                else:
                    status, body, headers = await self._make_request(url, method, param, payload, form_data)

                if self._detect_cmdi(body):
                    findings.append(PotentialVulnerability(
                        type='Command Injection',
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        confidence=0.8,
                        evidence_snippet=body[:200],
                        location=location,
                        path_index=path_index,
                        extra={'form_data': form_data}
                    ))
        return findings

    def _detect_cmdi(self, body: str) -> bool:
        patterns = ["uid=", "gid=", "root:x:", "bin/bash", "bin/sh", "total items", "drwx"]
        return any(p in body.lower() for p in patterns)


class OpenRedirectDetector(Detector):
    async def detect(self, param_info: dict, baseline: Optional[str] = None) -> List[PotentialVulnerability]:
        findings = []
        url = param_info['url']
        param = param_info['name']
        method = param_info['method']
        location_type = param_info.get('location', 'query')
        path_index = param_info.get('path_index')
        form_data = param_info.get('form_data')

        all_payloads = PayloadEngine.get_payloads('open_redirect')
        if self.payload_count > 0:
            all_payloads = all_payloads[:self.payload_count]

        for payload in all_payloads:
            try:
                if method == 'GET':
                    test_url = inject_into_url(url, param, payload, location_type, path_index)
                    async with self.session.get(test_url, allow_redirects=False) as resp:
                        self.request_counter()
                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get('Location', '')
                            # Check if payload is in Location OR redirects to a different domain
                            parsed_orig = urlparse(url)
                            parsed_loc = urlparse(urljoin(url, location))
                            if (payload in location) or (parsed_loc.netloc and parsed_loc.netloc != parsed_orig.netloc):
                                findings.append(PotentialVulnerability(
                                    type='Open Redirect',
                                    url=url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    confidence=0.9,
                                    evidence_snippet=f"Redirect to: {location}",
                                    location=location_type,
                                    path_index=path_index,
                                    extra={'form_data': form_data}
                                ))
                else:
                    # POST
                    data = form_data.copy() if form_data else {}
                    data[param] = payload
                    async with self.session.post(url, data=data, allow_redirects=False) as resp:
                        self.request_counter()
                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get('Location', '')
                            parsed_orig = urlparse(url)
                            parsed_loc = urlparse(urljoin(url, location))
                            if (payload in location) or (parsed_loc.netloc and parsed_loc.netloc != parsed_orig.netloc):
                                findings.append(PotentialVulnerability(
                                    type='Open Redirect',
                                    url=url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    confidence=0.9,
                                    evidence_snippet=f"Redirect to: {location}",
                                    location=location_type,
                                    path_index=path_index,
                                    extra={'form_data': form_data}
                                ))
            except Exception:
                pass
        return findings