"""
verification_engine.py
----------------------
Takes potential vulnerabilities and performs additional tests to confirm them.
Only confirmed vulnerabilities are passed to the report generator.
"""

import asyncio
import aiohttp
import logging
import time
import html
from typing import Optional, List, Dict
from urllib.parse import urljoin, urlparse

from .detector import PotentialVulnerability, inject_into_url
from .evidence_collector import EvidenceCollector, ConfirmedVulnerability

logger = logging.getLogger(__name__)


class RequestResponse:
    """Simple container for HTTP response details."""
    def __init__(self, status, headers, body, request_url, request_method, request_body):
        self.status = status
        self.headers = headers
        self.body = body
        self.request_url = request_url
        self.request_method = request_method
        self.request_body = request_body


class VerificationEngine:
    """
    Verifies potential vulnerabilities using more precise techniques.
    """

    def __init__(self, session: aiohttp.ClientSession, evidence_collector: EvidenceCollector):
        self.session = session
        self.evidence = evidence_collector

    async def verify(self, potential: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify a potential vulnerability and return confirmed if true."""
        method_name = f"_verify_{potential.type.lower().replace(' ', '_').replace('-', '_')}"
        verifier = getattr(self, method_name, None)
        if verifier:
            return await verifier(potential)
        else:
            # If no specific verifier, treat as confirmed if confidence high enough
            if potential.confidence >= 0.8:
                return await self._confirm_from_potential(potential)
        return None

    async def _confirm_from_potential(self, pot: PotentialVulnerability) -> ConfirmedVulnerability:
        """Create confirmed vulnerability without additional verification."""
        # We need a response; try to fetch one using the same payload
        resp = await self._make_request_raw(pot, pot.payload, allow_redirects=True)
        if not resp:
            # If no response, create minimal evidence
            resp = RequestResponse(
                status=0,
                headers={},
                body="",
                request_url=pot.url,
                request_method=pot.method,
                request_body=None
            )
        return await self._build_confirmed(pot, pot.payload, resp)

    async def _verify_sql_injection(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify SQLi by testing with two boolean payloads."""
        # Test with true and false conditions
        payload_true = "' AND '1'='1"
        payload_false = "' AND '1'='2"
        resp_true = await self._make_request_raw(pot, payload_true, allow_redirects=True)
        resp_false = await self._make_request_raw(pot, payload_false, allow_redirects=True)
        if resp_true and resp_false and resp_true.body != resp_false.body:
            return await self._build_confirmed(pot, pot.payload, resp_true, resp_false)
        return None

    async def _verify_sql_injection_time_based(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify time-based SQLi with SLEEP(5) and baseline."""
        baseline_time = await self._measure_time(pot, "1")
        attack_time = await self._measure_time(pot, pot.payload)
        if attack_time - baseline_time > 4:
            resp = await self._make_request_raw(pot, pot.payload, allow_redirects=True)
            return await self._build_confirmed(pot, pot.payload, resp)
        return None

    async def _verify_cross_site_scripting_xss(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify XSS by checking if payload is reflected unencoded."""
        resp = await self._make_request_raw(pot, pot.payload, allow_redirects=True)
        if resp and pot.payload in resp.body and html.escape(pot.payload) not in resp.body:
            return await self._build_confirmed(pot, pot.payload, resp)
        return None

    async def _verify_local_file_inclusion(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify LFI by checking for /etc/passwd content."""
        resp = await self._make_request_raw(pot, pot.payload, allow_redirects=True)
        if resp and any(p in resp.body for p in ["root:", "daemon:", "bin:"]):
            return await self._build_confirmed(pot, pot.payload, resp)
        return None

    async def _verify_server_side_request_forgery(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify SSRF by checking for connection errors or internal content."""
        resp = await self._make_request_raw(pot, pot.payload, allow_redirects=True)
        if resp:
            body_lower = resp.body.lower()
            if any(err in body_lower for err in ["connection refused", "failed to connect"]):
                return await self._build_confirmed(pot, pot.payload, resp)
            if "169.254.169.254" in body_lower or "metadata.google" in body_lower:
                return await self._build_confirmed(pot, pot.payload, resp)
            if "root:" in resp.body:
                return await self._build_confirmed(pot, pot.payload, resp)
        return None

    async def _verify_server_side_request_forgery_file_read(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Alias for same method."""
        return await self._verify_server_side_request_forgery(pot)

    async def _verify_command_injection(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify command injection by checking for command output."""
        resp = await self._make_request_raw(pot, pot.payload, allow_redirects=True)
        if resp and any(p in resp.body.lower() for p in ["uid=", "gid=", "root:x:"]):
            return await self._build_confirmed(pot, pot.payload, resp)
        return None

    async def _verify_command_injection_time_based(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify time-based command injection."""
        baseline_time = await self._measure_time(pot, "1")
        attack_time = await self._measure_time(pot, pot.payload)
        if attack_time - baseline_time > 4:
            resp = await self._make_request_raw(pot, pot.payload, allow_redirects=True)
            return await self._build_confirmed(pot, pot.payload, resp)
        return None

    async def _verify_open_redirect(self, pot: PotentialVulnerability) -> Optional[ConfirmedVulnerability]:
        """Verify open redirect by checking redirect location."""
        resp = await self._make_request_raw(pot, pot.payload, allow_redirects=False)
        if resp and resp.status in (301, 302, 303, 307, 308):
            location = resp.headers.get('Location', '')
            parsed_orig = urlparse(pot.url)
            parsed_loc = urlparse(urljoin(pot.url, location))
            if (pot.payload in location) or (parsed_loc.netloc and parsed_loc.netloc != parsed_orig.netloc):
                return await self._build_confirmed(pot, pot.payload, resp)
        return None

    async def _make_request_raw(self, pot: PotentialVulnerability, payload: str,
                                allow_redirects: bool = True) -> Optional[RequestResponse]:
        """Make a request based on potential vulnerability info."""
        try:
            if pot.method == 'GET':
                test_url = inject_into_url(pot.url, pot.parameter, payload,
                                           pot.location, pot.path_index)
                async with self.session.get(test_url, allow_redirects=allow_redirects) as resp:
                    body = await resp.text()
                    return RequestResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        request_url=test_url,
                        request_method=pot.method,
                        request_body=None
                    )
            else:
                # POST
                data = pot.extra.get('form_data', {}).copy() if pot.extra else {}
                data[pot.parameter] = payload
                async with self.session.post(pot.url, data=data, allow_redirects=allow_redirects) as resp:
                    body = await resp.text()
                    return RequestResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        request_url=pot.url,
                        request_method=pot.method,
                        request_body=data
                    )
        except Exception as e:
            logger.debug(f"Request error: {e}")
            return None

    async def _measure_time(self, pot: PotentialVulnerability, payload: str) -> float:
        start = time.time()
        await self._make_request_raw(pot, payload, allow_redirects=True)
        return time.time() - start

    async def _build_confirmed(self, pot: PotentialVulnerability, payload: str,
                               resp: Optional[RequestResponse] = None,
                               extra_resp: Optional[RequestResponse] = None) -> ConfirmedVulnerability:
        """Build a ConfirmedVulnerability from potential and evidence."""
        # Use evidence collector to create full evidence
        if not resp:
            # Create a dummy response
            resp = RequestResponse(
                status=0,
                headers={},
                body="",
                request_url=pot.url,
                request_method=pot.method,
                request_body=None
            )
        evidence = self.evidence.collect(pot, payload, resp, extra_resp)
        return ConfirmedVulnerability(
            type=pot.type,
            url=pot.url,
            parameter=pot.parameter,
            method=pot.method,
            payload=payload,
            severity=self._map_severity(pot.type),
            cvss=self._map_cvss(pot.type),
            cwe=self._map_cwe(pot.type),
            owasp=self._map_owasp(pot.type),
            description=f"{pot.type} in parameter {pot.parameter}",
            evidence=evidence
        )

    def _map_severity(self, vuln_type: str) -> str:
        mapping = {
            'SQL Injection': 'Critical',
            'SQL Injection (Time-based)': 'Critical',
            'Command Injection': 'Critical',
            'Command Injection (Time-based)': 'Critical',
            'Cross-Site Scripting (XSS)': 'High',
            'Server-Side Request Forgery': 'High',
            'Server-Side Request Forgery (File Read)': 'High',
            'Local File Inclusion': 'High',
            'Open Redirect': 'Medium',
        }
        return mapping.get(vuln_type, 'Medium')

    def _map_cvss(self, vuln_type: str) -> float:
        mapping = {
            'SQL Injection': 9.8,
            'Command Injection': 10.0,
            'Cross-Site Scripting (XSS)': 7.3,
            'Server-Side Request Forgery': 9.1,
            'Local File Inclusion': 8.2,
            'Open Redirect': 5.3,
        }
        return mapping.get(vuln_type, 5.0)

    def _map_cwe(self, vuln_type: str) -> str:
        mapping = {
            'SQL Injection': 'CWE-89',
            'Command Injection': 'CWE-78',
            'Cross-Site Scripting (XSS)': 'CWE-79',
            'Server-Side Request Forgery': 'CWE-918',
            'Local File Inclusion': 'CWE-22',
            'Open Redirect': 'CWE-601',
        }
        return mapping.get(vuln_type, 'CWE-000')

    def _map_owasp(self, vuln_type: str) -> str:
        mapping = {
            'SQL Injection': 'A03:2021',
            'Command Injection': 'A03:2021',
            'Cross-Site Scripting (XSS)': 'A03:2021',
            'Server-Side Request Forgery': 'A10:2021',
            'Local File Inclusion': 'A01:2021',
            'Open Redirect': 'A01:2021',
        }
        return f"OWASP {mapping.get(vuln_type, 'Unknown')}"