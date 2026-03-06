"""
evidence_collector.py
---------------------
Collects and formats full HTTP request/response evidence for confirmed vulnerabilities.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import urllib.parse


@dataclass
class Evidence:
    """Complete evidence for a vulnerability."""
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    payload: str
    parameter: str
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfirmedVulnerability:
    """Confirmed vulnerability with full evidence."""
    type: str
    url: str
    parameter: str
    method: str
    payload: str
    severity: str
    cvss: float
    cwe: str
    owasp: str
    description: str
    evidence: Evidence


class EvidenceCollector:
    """Collects and formats evidence from requests."""

    def collect(self, pot, payload: str, resp, extra_resp=None) -> Evidence:
        """
        Build evidence from a potential vulnerability and the response(s).
        """
        # Build request headers (simplified)
        request_headers = {
            'Host': urllib.parse.urlparse(resp.request_url).netloc,
            'User-Agent': 'VAPT Scanner/4.0',
        }
        if resp.request_method == 'POST' and resp.request_body:
            request_headers['Content-Type'] = 'application/x-www-form-urlencoded'

        evidence = Evidence(
            request_method=resp.request_method,
            request_url=resp.request_url,
            request_headers=request_headers,
            request_body=urllib.parse.urlencode(resp.request_body) if resp.request_body else None,
            response_status=resp.status,
            response_headers=resp.headers,
            response_body=resp.body,
            payload=payload,
            parameter=pot.parameter,
            extra={'confidence': pot.confidence}
        )
        return evidence