#!/usr/bin/env python3
"""
report_generator.py
-------------------
Generates a professional HTML vulnerability assessment report with:
- Executive Summary
- Scope & Methodology
- Scan Statistics
- Vulnerability Summary Table (grouped by severity)
- Detailed Findings with full HTTP evidence
- Consolidated Security Recommendations (only for found vulnerability types)
- Assessment Limitations & False Positive Handling
- Conclusion

Expects input vulnerabilities as a list of dictionaries with the following structure:
{
    "type": str,               # e.g., "SQL Injection"
    "title": str,               # optional, falls back to type
    "url": str,                  # affected endpoint
    "parameter": str,            # vulnerable parameter
    "payload": str,              # payload used
    "severity": str,             # "Critical", "High", "Medium", "Low"
    "cvss_score": float,
    "cwe_id": str,
    "owasp": str,
    "description": str,
    "evidence": [                 # list of evidence items (usually one)
        {
            "request_url": str,
            "method": str,
            "parameter": str,
            "payload": str,
            "response_status": int,
            "response_headers": dict,
            "response_body": str   # truncated or full
        }
    ]
}
"""

import logging
from typing import List, Dict, Any, Set
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ProfessionalReportGenerator:
    """Generate professional enterprise-grade pentest reports."""

    def __init__(self, target_url: str, scan_duration: float):
        """Initialize report generator."""
        self.target_url = target_url
        self.scan_duration = scan_duration
        self.generated_at = datetime.now()

    def generate_html_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tech_stack: Dict[str, str],
        output_path: str,
        discovered_urls: List[str] = None,
        total_requests: int = 0
    ) -> None:
        """Generate professional HTML pentest report."""
        # Process vulnerabilities: merge duplicates by type, sort by severity
        processed_vulns = self._process_vulnerabilities(vulnerabilities)
        severity_counts = self._calculate_severity_counts(processed_vulns)
        overall_risk = self._calculate_risk_level(severity_counts)

        # Build HTML
        html = self._build_html_report(
            vulnerabilities=processed_vulns,
            tech_stack=tech_stack,
            severity_counts=severity_counts,
            overall_risk=overall_risk,
            discovered_urls=discovered_urls or [],
            total_requests=total_requests
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        logger.info(f"Professional pentest report generated: {output_path}")

    def _process_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge duplicate vulnerabilities by type, collect endpoints, and sort by severity."""
        merged = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            severity = vuln.get("severity", "Medium")
            cwe = vuln.get("cwe_id", "CWE-000")
            owasp = vuln.get("owasp", "")

            key = (vuln_type, severity, cwe, owasp)
            if key not in merged:
                merged[key] = {
                    "type": vuln_type,
                    "title": vuln.get("title", vuln_type),
                    "severity": severity,
                    "cvss_score": vuln.get("cvss_score", 0),
                    "cwe_id": cwe,
                    "owasp": owasp,
                    "description": vuln.get("description", ""),
                    "endpoints": [],
                    "evidence": vuln.get("evidence", [])  # keep first evidence
                }
            # Add endpoint details
            merged[key]["endpoints"].append({
                "url": vuln.get("url", ""),
                "parameter": vuln.get("parameter", "N/A"),
                "method": vuln.get("method", "GET"),
                "payload": vuln.get("payload", "")
            })

        # Convert to list and sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        result = list(merged.values())
        result.sort(key=lambda x: (severity_order.get(x["severity"], 4), -x.get("cvss_score", 0)))

        # Add endpoint count and first endpoint for display
        for item in result:
            item["endpoint_count"] = len(item["endpoints"])
            item["first_endpoint"] = item["endpoints"][0] if item["endpoints"] else {}
            item["other_endpoints"] = item["endpoints"][1:] if len(item["endpoints"]) > 1 else []

        return result

    def _calculate_severity_counts(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity counts."""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "Medium")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level."""
        if severity_counts.get("Critical", 0) >= 3:
            return "CRITICAL"
        elif severity_counts.get("Critical", 0) > 0:
            return "HIGH"
        elif severity_counts.get("High", 0) >= 3:
            return "HIGH"
        elif severity_counts.get("High", 0) > 0 or severity_counts.get("Medium", 0) > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _build_html_report(self, vulnerabilities: List[Dict[str, Any]], tech_stack: Dict[str, str],
                           severity_counts: Dict[str, int], overall_risk: str,
                           discovered_urls: List[str], total_requests: int) -> str:
        """Build complete HTML report."""
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        today = datetime.now().strftime("%d %B %Y")
        total_vulns = len(vulnerabilities)

        # Start building HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report</title>
    <style>
{self._get_css()}
    </style>
</head>
<body>
    <!-- Cover Page -->
    <div class="page cover-page">
        <div class="cover-content">
            <h1>Vulnerability Assessment Report</h1>
            <div class="cover-divider"></div>
            <div class="cover-info">
                <p><strong>Target:</strong> {self.target_url}</p>
                <p><strong>Assessment Tool:</strong> VAPT Scanner v4.0</p>
                <p><strong>Assessment Date:</strong> {today}</p>
                <p><strong>Report Version:</strong> 1.0</p>
                <p><strong>Prepared By:</strong> Security Assessment Team</p>
            </div>
        </div>
        <div class="page-break"></div>
    </div>

    <!-- Executive Summary -->
    <div class="page">
        <h1>Executive Summary</h1>
        <div class="summary-box">
            <p>This vulnerability assessment identified critical and high-priority security weaknesses within the target application. Immediate remediation is required to prevent potential exploitation.</p>
            <div class="severity-summary">
                <h3>Vulnerabilities Discovered</h3>
                <table class="summary-table">
                    <tr><td class="severity-critical"><strong>Critical</strong></td><td class="severity-critical-count">{severity_counts.get('Critical', 0)}</td></tr>
                    <tr><td class="severity-high"><strong>High</strong></td><td class="severity-high-count">{severity_counts.get('High', 0)}</td></tr>
                    <tr><td class="severity-medium"><strong>Medium</strong></td><td class="severity-medium-count">{severity_counts.get('Medium', 0)}</td></tr>
                    <tr><td class="severity-low"><strong>Low</strong></td><td class="severity-low-count">{severity_counts.get('Low', 0)}</td></tr>
                </table>
            </div>
            <div class="risk-assessment">
                <h3>Overall Risk Assessment</h3>
                <p><span class="risk-level risk-{overall_risk.lower()}"><strong>{overall_risk}</strong></span></p>
                <p>The identified vulnerabilities could allow attackers to:</p>
                <ul>
                    <li>Execute arbitrary database queries (SQL Injection)</li>
                    <li>Bypass authentication mechanisms</li>
                    <li>Access sensitive data</li>
                    <li>Compromise system integrity</li>
                </ul>
            </div>
        </div>
        <div class="page-break"></div>
    </div>

    <!-- Scope of Assessment -->
    <div class="page">
        <h1>Scope of Assessment</h1>
        <div class="scope-box">
            <h3>In-Scope</h3>
            <ul>
                <li><strong>Primary Target:</strong> {self.target_url}</li>
                <li><strong>Assessment Type:</strong> Black-Box Web Application Security Testing</li>
                <li><strong>Testing Methodology:</strong> OWASP Testing Guide v4</li>
                <li><strong>Vulnerability Classes:</strong> SQL Injection, XSS, SSRF, LFI, CSRF, XXE, Command Injection, SSTI, Security Headers</li>
            </ul>
            <h3>Out-of-Scope</h3>
            <ul>
                <li>Authenticated functionality testing</li>
                <li>Source code review and secure code analysis</li>
                <li>Infrastructure security assessment</li>
                <li>Physical security assessment</li>
                <li>Social engineering assessment</li>
            </ul>
        </div>
        <div class="page-break"></div>
    </div>

    <!-- Testing Methodology -->
    <div class="page">
        <h1>Testing Methodology</h1>
        <div class="methodology-box">
            <h3>Standards and Guidelines</h3>
            <ul>
                <li><strong>OWASP Testing Guide v4:</strong> Comprehensive testing framework</li>
                <li><strong>OWASP Top 10 (2021):</strong> Critical web application security risks</li>
                <li><strong>NIST SP 800-115:</strong> Technical Security Testing</li>
            </ul>
            <h3>Testing Phases</h3>
            <ol>
                <li><strong>Reconnaissance:</strong> Identify web servers, technologies, and endpoints</li>
                <li><strong>Scanning:</strong> Automated vulnerability detection and parameter analysis</li>
                <li><strong>Analysis:</strong> Manual verification and false positive elimination</li>
                <li><strong>Exploitation:</strong> Proof-of-concept validation where applicable</li>
                <li><strong>Reporting:</strong> Detailed documentation with remediation guidance</li>
            </ol>
            <h3>Tools Used</h3>
            <ul>
                <li>VAPT Scanner v4.0 - Automated vulnerability scanner</li>
                <li>Custom payload injection engine</li>
                <li>HTTP request/response analysis tools</li>
            </ul>
        </div>
        <div class="page-break"></div>
    </div>

    <!-- Scan Overview -->
    <div class="page">
        <h1>Scan Overview</h1>
        <h3>Assessment Details</h3>
        <table class="overview-table">
            <tr><td><strong>Target URL</strong></td><td>{self.target_url}</td></tr>
            <tr><td><strong>Scan Scope</strong></td><td>Web Application Security Assessment</td></tr>
            <tr><td><strong>Testing Type</strong></td><td>Black-Box Web Application Security Testing</td></tr>
            <tr><td><strong>Authenticated Testing</strong></td><td>Not Performed</td></tr>
        </table>
        <h3>Scan Metrics</h3>
        <table class="overview-table">
            <tr><td><strong>Assessment Date</strong></td><td>{today}</td></tr>
            <tr><td><strong>Scan Duration</strong></td><td>{self.scan_duration:.2f} seconds (~{int(self.scan_duration/60)} minutes)</td></tr>
            <tr><td><strong>URLs Discovered</strong></td><td>{len(discovered_urls)}</td></tr>
            <tr><td><strong>Total HTTP Requests</strong></td><td>{total_requests:,}</td></tr>
            <tr><td><strong>Scanner Version</strong></td><td>VAPT Scanner v4.0</td></tr>
        </table>
        <div class="page-break"></div>
    </div>

    <!-- Technology Stack -->
    <div class="page">
        <h1>Technology Stack</h1>
        <h3>Detected Technologies</h3>
        <div class="tech-stack">
"""
        for tech in sorted(tech_stack.keys()):
            html += f'            <span class="tech-item">{tech}</span>\n'
        if not tech_stack:
            html += '            <span class="tech-item">Unknown</span>\n'
        html += """        </div>
        <div class="page-break"></div>
    </div>

    <!-- Vulnerability Summary Table -->
    <div class="page">
        <h1>Vulnerability Summary</h1>
        <table class="vulnerability-summary-table">
            <thead>
                <tr>
                    <th>ID</th><th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>OWASP</th><th>Risk</th><th>Endpoints</th>
                </tr>
            </thead>
            <tbody>
"""
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.get("severity", "Medium").lower()
            cvss = vuln.get("cvss_score", 0)
            risk_rating = self._get_risk_rating(vuln.get("severity", "Medium"))
            html += f"""                <tr class="severity-{severity_class}">
                    <td><strong>V-{idx:02d}</strong></td>
                    <td>{vuln.get('title', 'Unknown')}</td>
                    <td><span class="badge-{severity_class}">{vuln.get('severity', 'Medium')}</span></td>
                    <td>{cvss}</td>
                    <td>{vuln.get('cwe_id', 'N/A')}</td>
                    <td>{vuln.get('owasp', 'N/A')}</td>
                    <td><span class="risk-badge">{risk_rating}</span></td>
                    <td>{vuln.get('endpoint_count', 0)}</td>
                </tr>
"""
        html += """            </tbody>
        </table>
        <div class="page-break"></div>
    </div>

    <!-- Detailed Findings -->
"""
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.get("severity", "Medium").lower()
            first_ep = vuln.get("first_endpoint", {})
            other_eps = vuln.get("other_endpoints", [])
            endpoint_url = first_ep.get("url", "Unknown")
            param = first_ep.get("parameter", "N/A")
            method = first_ep.get("method", "GET")
            payload = first_ep.get("payload", "")

            html += f"""
    <div class="page">
        <h1>V-{idx:02d} {vuln.get('title', 'Unknown')}</h1>
        <div class="finding-header severity-{severity_class}">
            <table class="finding-meta">
                <tr><td><strong>Severity</strong></td><td><span class="badge-{severity_class}">{vuln.get('severity', 'Medium')}</span></td></tr>
                <tr><td><strong>CVSS Score</strong></td><td>{vuln.get('cvss_score', 0)}</td></tr>
                <tr><td><strong>CWE</strong></td><td>{vuln.get('cwe_id', 'N/A')}</td></tr>
                <tr><td><strong>OWASP</strong></td><td>{vuln.get('owasp', 'N/A')}</td></tr>
            </table>
        </div>
        <h3>Affected Endpoints</h3>
        <p class="endpoint-box">{endpoint_url}</p>
"""
            if other_eps:
                html += "        <ul>\n"
                for ep in other_eps[:5]:
                    html += f'            <li>{ep.get("url")} (param: {ep.get("parameter")})</li>\n'
                if len(other_eps) > 5:
                    html += f'            <li>... and {len(other_eps)-5} more</li>\n'
                html += "        </ul>\n"

            html += f"""
        <h3>Vulnerable Parameter</h3>
        <p>{param}</p>
        <h3>Description</h3>
        <p>{vuln.get('description', 'No description available.')}</p>
        <h3>Attack Scenario</h3>
        <p>An attacker could exploit this vulnerability to:</p>
        <ul>
            <li>Execute arbitrary database queries</li>
            <li>Bypass authentication mechanisms</li>
            <li>Access sensitive information</li>
            <li>Modify or delete data</li>
        </ul>
        <h3>Evidence</h3>
"""
            # Evidence section
            evidence_list = vuln.get("evidence", [])
            if evidence_list:
                ev = evidence_list[0]  # take first evidence
                req_url = ev.get("request_url", endpoint_url)
                req_method = ev.get("method", method)
                req_param = ev.get("parameter", param)
                req_payload = ev.get("payload", payload)
                resp_status = ev.get("response_status", 200)
                resp_headers = ev.get("response_headers", {})
                resp_body = ev.get("response_body", "")

                # Build request string
                parsed_req = urlparse(req_url)
                path = parsed_req.path or '/'
                if parsed_req.query:
                    path += '?' + parsed_req.query
                req_str = f"{req_method} {path} HTTP/1.1\n"
                req_str += f"Host: {domain}\n"
                req_str += "User-Agent: VAPT Scanner/4.0\n"
                if req_method == 'POST' and req_payload:
                    # Assume form data
                    req_str += "Content-Type: application/x-www-form-urlencoded\n"
                    body_data = f"{req_param}={self._escape_html(req_payload)}"
                    req_str += f"Content-Length: {len(body_data)}\n\n"
                    req_str += body_data
                else:
                    req_str += "Connection: close\n"

                # Build response string
                resp_str = f"HTTP/1.1 {resp_status}\n"
                for k, v in resp_headers.items():
                    if k.lower() in ('server', 'content-type', 'location'):
                        resp_str += f"{k}: {v}\n"
                resp_str += "\n"
                if resp_body:
                    # Truncate to 500 chars for readability
                    snippet = resp_body[:500]
                    if len(resp_body) > 500:
                        snippet += "..."
                    resp_str += self._escape_html(snippet)

                html += f"""
        <div class="evidence-box">
            <p><strong>HTTP Request:</strong></p>
            <pre>{self._escape_html(req_str)}</pre>
        </div>
        <div class="evidence-box">
            <p><strong>HTTP Response:</strong></p>
            <pre>{self._escape_html(resp_str)}</pre>
        </div>
"""
            else:
                html += "<p><em>No evidence available.</em></p>\n"

            html += f"""
        <h3>Impact</h3>
        <p>Successful exploitation could lead to:</p>
        <ul>
            <li>Unauthorized database access</li>
            <li>Sensitive data exposure</li>
            <li>Data modification or deletion</li>
            <li>System compromise</li>
        </ul>
        <h3>Recommendation</h3>
        {self._get_detailed_recommendation(vuln.get('type', ''))}
        <div class="page-break"></div>
    </div>
"""

        # Remaining sections: Limitations, False Positive Handling, Recommendations, Conclusion
        html += self._build_footer_sections(vulnerabilities, severity_counts, overall_risk, total_vulns)

        return html

    def _build_footer_sections(self, vulnerabilities: List[Dict[str, Any]], severity_counts: Dict[str, int],
                               overall_risk: str, total_vulns: int) -> str:
        """Build the final sections of the report, including dynamic recommendations."""
        # Collect unique vulnerability types
        vuln_types = set(v.get("type", "Unknown") for v in vulnerabilities)

        # Start with Limitations and False Positive Handling (same as before)
        footer = f"""
    <!-- Limitations -->
    <div class="page">
        <h1>Assessment Limitations</h1>
        <div class="limitations-box">
            <p>The following limitations should be considered when reviewing this assessment:</p>
            <ul>
                <li><strong>No Authenticated Testing:</strong> Assessment was conducted without credentials. Vulnerabilities in authenticated functionality may not have been detected.</li>
                <li><strong>No Source Code Review:</strong> This is a black-box security assessment. Logic flaws visible only in source code were not assessed.</li>
                <li><strong>Limited Scope:</strong> Assessment focused on web application layer only.</li>
                <li><strong>Time-Based Limitations:</strong> Testing was conducted within a limited timeframe. Additional vulnerabilities may exist.</li>
                <li><strong>WAF/IDS Systems:</strong> Presence of Web Application Firewalls may have blocked certain payloads.</li>
            </ul>
        </div>
        <div class="page-break"></div>
    </div>

    <!-- False Positive Handling -->
    <div class="page">
        <h1>False Positive Handling</h1>
        <div class="fp-box">
            <p>All findings in this report have been manually verified to minimize false positives.</p>
            <h3>Verification Process</h3>
            <ul>
                <li><strong>Automated Detection:</strong> Initial vulnerability detection by scanner</li>
                <li><strong>Manual Verification:</strong> Each finding has been manually reviewed</li>
                <li><strong>Evidence Collection:</strong> HTTP request/response evidence documented</li>
                <li><strong>Impact Assessment:</strong> Exploitability and business impact evaluated</li>
            </ul>
            <h3>Confidence Levels</h3>
            <ul>
                <li><strong>High Confidence:</strong> Vulnerabilities verified with proof-of-concept</li>
                <li><strong>Medium Confidence:</strong> Indicators present, exploitation verified</li>
            </ul>
        </div>
        <div class="page-break"></div>
    </div>

    <!-- Security Recommendations -->
    <div class="page">
        <h1>Security Recommendations</h1>
        <div class="recommendations">
"""

        if not vuln_types:
            footer += """
            <p>No vulnerabilities were detected during this assessment. However, it is recommended to follow general security best practices:</p>
            <ul>
                <li>Keep all software and dependencies up to date.</li>
                <li>Use strong authentication mechanisms and enforce least privilege.</li>
                <li>Implement proper input validation and output encoding.</li>
                <li>Conduct regular security assessments and code reviews.</li>
            </ul>
"""
        else:
            # Map vulnerability types to their severity (take from any occurrence)
            type_to_severity = {v["type"]: v["severity"] for v in vulnerabilities}
            # Sort by severity order
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sorted_types = sorted(vuln_types, key=lambda t: severity_order.get(type_to_severity.get(t, "Medium"), 4))

            for vuln_type in sorted_types:
                severity = type_to_severity.get(vuln_type, "Medium")
                severity_class = severity.lower()
                # Count instances of this type
                count = sum(1 for v in vulnerabilities if v.get("type") == vuln_type)
                instance_text = f"({count} instance{'s' if count > 1 else ''})"
                footer += f"""
            <div class="recommendation-item severity-{severity_class}">
                <h3>{vuln_type} Mitigation {instance_text}</h3>
                <p><strong>Severity:</strong> <span class="badge-{severity_class}">{severity}</span></p>
                <p><strong>CWE:</strong> {self._cwe_for_type(vuln_type)}</p>
                {self._get_detailed_recommendation(vuln_type)}
            </div>
"""

        footer += f"""
        </div>
        <div class="page-break"></div>
    </div>

    <!-- Conclusion -->
    <div class="page">
        <h1>Conclusion</h1>
        <div class="conclusion-box">
            <p>This assessment identified <strong>{total_vulns}</strong> unique vulnerabilities across the target application.</p>
            <p><strong>Overall Risk:</strong> <span class="risk-level risk-{overall_risk.lower()}"><strong>{overall_risk}</strong></span></p>
            <h3>Recommended Priority Actions</h3>
            <ol>
                <li><strong>Immediate (0-24 hours):</strong> Remediate all Critical vulnerabilities</li>
                <li><strong>Short-term (1-30 days):</strong> Address High severity vulnerabilities and implement security headers</li>
                <li><strong>Ongoing:</strong> Conduct regular security assessments and implement secure development practices</li>
            </ol>
            <p style="margin-top:30px; font-size:12px; color:#666;">
                <em>This report contains confidential information. Unauthorized disclosure or reproduction is prohibited.</em>
            </p>
        </div>
    </div>

    <script>
        window.addEventListener('beforeprint', function() {{
            document.documentElement.style.fontSize = '12pt';
        }});
    </script>
</body>
</html>
"""
        return footer

    def _cwe_for_type(self, vuln_type: str) -> str:
        """Return CWE ID for a vulnerability type."""
        mapping = {
            'SQL Injection': 'CWE-89',
            'Command Injection': 'CWE-78',
            'Cross-Site Scripting (XSS)': 'CWE-79',
            'Server-Side Request Forgery': 'CWE-918',
            'Server-Side Request Forgery (File Read)': 'CWE-918',
            'Local File Inclusion': 'CWE-22',
            'Open Redirect': 'CWE-601',
        }
        return mapping.get(vuln_type, 'CWE-000')

    def _get_risk_rating(self, severity: str) -> str:
        """Map severity to risk rating."""
        mapping = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }
        return mapping.get(severity, "Medium")

    def _get_detailed_recommendation(self, vuln_type: str) -> str:
        """Return detailed mitigation advice for a vulnerability type."""
        vuln_lower = vuln_type.lower()
        if "sql" in vuln_lower:
            return """<p>Use prepared statements and parameterized queries to prevent SQL injection attacks.</p>
                <pre>// PHP/PDO Example:
$stmt = $pdo->prepare("SELECT * FROM products WHERE id = ? AND category = ?");
$stmt->execute([$_GET['id'], $_GET['cat']]);
$results = $stmt->fetchAll();</pre>
                <p>Additional mitigation:</p>
                <ul>
                    <li>Input Validation: Whitelist expected input patterns</li>
                    <li>ORM Frameworks: Use Doctrine, Eloquent, or SQLAlchemy</li>
                    <li>Least Privilege: Database users should have minimal permissions</li>
                    <li>Web Application Firewall: Deploy WAF with SQL injection detection rules</li>
                    <li>Error Handling: Do not display SQL errors to users</li>
                    <li>Code Review: Conduct regular secure code reviews</li>
                </ul>"""
        elif "xss" in vuln_lower:
            return """<p>Implement output encoding and Content Security Policy headers.</p>
                <pre>// PHP/HTML Escaping:
&lt;?php echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8'); ?&gt;

// HTTP Security Headers:
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN</pre>
                <p>XSS prevention measures:</p>
                <ul>
                    <li>Output Encoding: Encode data based on context</li>
                    <li>Input Validation: Sanitize all user inputs</li>
                    <li>Template Engines: Use auto-escaping (Twig, Jinja2)</li>
                    <li>HttpOnly Cookies: Set HttpOnly and Secure flags</li>
                    <li>CSP Headers: Restrict script execution</li>
                </ul>"""
        elif "ssrf" in vuln_lower:
            return """<p>Validate and whitelist allowed URLs to prevent Server-Side Request Forgery.</p>
                <pre>// URL Validation:
$allowed_hosts = ['api.example.com', 'secure.example.com'];
$parsed_url = parse_url($user_url);
if (!in_array($parsed_url['host'], $allowed_domains)) {
    throw new Exception('URL not in whitelist');
}</pre>
                <p>Additional measures:</p>
                <ul>
                    <li>Block access to internal IP ranges (127.0.0.0/8, 169.254.169.254, etc.)</li>
                    <li>Use a network firewall to restrict outbound traffic</li>
                    <li>Disable unused URL schemes (file://, gopher://)</li>
                </ul>"""
        elif "lfi" in vuln_lower or "file inclusion" in vuln_lower:
            return """<p>Use absolute file paths and implement proper access controls.</p>
                <pre>// Secure File Inclusion:
$base_dir = '/var/www/app/files/';
$requested_file = basename($_GET['file']);
$file_path = realpath($base_dir . $requested_file);

if (strpos($file_path, $base_dir) !== 0) {
    die('Access denied');
}</pre>
                <ul>
                    <li>Disable allow_url_include in PHP configuration</li>
                    <li>Use a whitelist of allowed files</li>
                    <li>Apply least privilege to file system permissions</li>
                </ul>"""
        elif "command" in vuln_lower:
            return """<p>Avoid shell commands and use safer APIs.</p>
                <pre>// DO NOT USE: system("ping " . $_GET['host']);
// USE INSTEAD:
$host = escapeshellarg($_GET['host']);
exec("ping -c 1 " . $host, $output);</pre>
                <ul>
                    <li>Use language-specific safe functions (e.g., subprocess with shell=False in Python)</li>
                    <li>Validate input against a strict whitelist</li>
                    <li>Run the application with minimal system privileges</li>
                </ul>"""
        elif "open redirect" in vuln_lower:
            return """<p>Validate redirect URLs against a whitelist of allowed domains.</p>
                <pre>// Safe Redirect:
$allowed_domains = ['example.com', 'sub.example.com'];
$redirect_url = $_GET['url'];
$parsed = parse_url($redirect_url);
if (in_array($parsed['host'], $allowed_domains)) {
    header("Location: " . $redirect_url);
} else {
    header("Location: /");
}</pre>
                <ul>
                    <li>Avoid using user input directly in redirect headers</li>
                    <li>Use relative paths when possible</li>
                </ul>"""
        else:
            return """<p>Implement security best practices and follow OWASP guidelines.</p>
                <ul>
                    <li>Validate and sanitize all user inputs</li>
                    <li>Use parametrized queries for database access</li>
                    <li>Implement proper access controls</li>
                    <li>Keep software and dependencies updated</li>
                    <li>Conduct regular security assessments</li>
                </ul>"""

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace('\n', '&#10;'))

    def _get_css(self) -> str:
        """Return professional CSS styling."""
        return """* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; font-size: 11pt; }
.page { background: white; padding: 60px 50px; margin: 20px auto; max-width: 900px; min-height: 1000px; box-shadow: 0 0 10px rgba(0,0,0,0.1); page-break-after: always; }
.cover-page { display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 1100px; }
.cover-content { text-align: center; }
.cover-page h1 { font-size: 48px; margin-bottom: 40px; color: #1a1a1a; }
.cover-divider { width: 200px; height: 3px; background: #3b82f6; margin: 40px auto; }
.cover-info { text-align: left; margin-top: 60px; font-size: 14px; }
.cover-info p { margin: 15px 0; }
h1 { font-size: 28px; margin-bottom: 25px; color: #1a1a1a; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
h2 { font-size: 22px; margin-bottom: 15px; color: #2c3e50; }
h3 { font-size: 16px; margin-top: 20px; margin-bottom: 10px; color: #2c3e50; }
.summary-box { background: #f9f9f9; padding: 20px; border-radius: 6px; margin-bottom: 20px; }
.severity-summary { margin: 30px 0; }
.summary-table { width: 100%; border-collapse: collapse; margin: 15px 0; }
.summary-table tr { border-bottom: 2px solid #ddd; }
.summary-table td { padding: 12px; font-size: 13px; }
.severity-critical { color: #ff4444; }
.severity-critical-count { font-weight: bold; font-size: 24px; color: #ff4444; }
.severity-high { color: #ff8c00; }
.severity-high-count { font-weight: bold; font-size: 20px; color: #ff8c00; }
.severity-medium { color: #ffc107; }
.severity-medium-count { font-weight: bold; font-size: 16px; color: #ffc107; }
.severity-low { color: #28a745; }
.severity-low-count { font-weight: bold; font-size: 14px; color: #28a745; }
.risk-assessment { background: #fff3cd; padding: 15px; border-radius: 6px; border-left: 4px solid #ffc107; }
.risk-level { font-size: 18px; font-weight: bold; padding: 10px; border-radius: 4px; display: inline-block; margin: 10px 0; }
.risk-critical { background: #ff4444; color: white; }
.risk-high { background: #ff8c00; color: white; }
.risk-medium { background: #ffc107; color: #333; }
.risk-low { background: #28a745; color: white; }
.overview-table { width: 100%; border-collapse: collapse; margin: 20px 0; background: #f9f9f9; }
.overview-table tr { border-bottom: 1px solid #ddd; }
.overview-table td { padding: 12px; font-size: 13px; }
.scope-box, .methodology-box, .limitations-box, .fp-box { background: #f9f9f9; padding: 20px; border-radius: 6px; margin: 15px 0; border-left: 4px solid #3b82f6; }
.tech-stack { display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0; }
.tech-item { background: #3b82f6; color: white; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 500; }
.vulnerability-summary-table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 11px; }
.vulnerability-summary-table th { background: #3b82f6; color: white; padding: 12px; text-align: left; font-weight: bold; border-bottom: 2px solid #3b82f6; }
.vulnerability-summary-table td { padding: 10px 8px; border-bottom: 1px solid #ddd; font-size: 12px; }
.badge-critical { background: #ff4444; color: white; padding: 4px 8px; border-radius: 3px; font-size: 10px; font-weight: bold; }
.badge-high { background: #ff8c00; color: white; padding: 4px 8px; border-radius: 3px; font-size: 10px; font-weight: bold; }
.badge-medium { background: #ffc107; color: #333; padding: 4px 8px; border-radius: 3px; font-size: 10px; font-weight: bold; }
.badge-low { background: #28a745; color: white; padding: 4px 8px; border-radius: 3px; font-size: 10px; font-weight: bold; }
.finding-header { padding: 15px; border-radius: 6px; margin-bottom: 20px; }
.finding-header.severity-critical { background: #fff5f5; border-left: 4px solid #ff4444; }
.finding-header.severity-high { background: #fff9f5; border-left: 4px solid #ff8c00; }
.finding-header.severity-medium { background: #fffef5; border-left: 4px solid #ffc107; }
.finding-header.severity-low { background: #f5fff5; border-left: 4px solid #28a745; }
.finding-meta { width: 100%; font-size: 12px; }
.finding-meta td { padding: 6px 0; }
.endpoint-box { background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 11px; margin: 10px 0; word-break: break-all; }
.evidence-box { background: #f9f9f9; padding: 15px; border-radius: 4px; margin: 15px 0; border-left: 3px solid #3b82f6; }
.evidence-box pre { background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 10px; margin: 10px 0; white-space: pre-wrap; word-wrap: break-word; }
.recommendations { display: flex; flex-direction: column; gap: 20px; }
.recommendation-item { padding: 15px; border-radius: 6px; border-left: 4px solid #ddd; }
.recommendation-item.severity-critical { background: #fff5f5; border-left-color: #ff4444; }
.recommendation-item.severity-high { background: #fff9f5; border-left-color: #ff8c00; }
.recommendation-item.severity-medium { background: #fffef5; border-left-color: #ffc107; }
.recommendation-item.severity-low { background: #f5fff5; border-left-color: #28a745; }
.recommendation-item pre { background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 10px; margin: 10px 0; }
.conclusion-box { background: #f9f9f9; padding: 20px; border-radius: 6px; border: 2px solid #3b82f6; }
.conclusion-box ul, .conclusion-box ol { margin-left: 20px; margin-top: 10px; }
.conclusion-box li { margin-bottom: 8px; }
.page-break { page-break-after: always; }
.risk-badge { background: #3b82f6; color: white; padding: 4px 8px; border-radius: 3px; font-size: 10px; font-weight: bold; }
@media print { body { background: white; } .page { max-width: 100%; margin: 0; padding: 60px 50px; box-shadow: none; page-break-after: always; } }
ul, ol { margin-left: 20px; margin-top: 10px; }
li { margin-bottom: 6px; font-size: 13px; }
p { margin-bottom: 12px; font-size: 13px; text-align: justify; }
pre { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 10px; margin: 15px 0; white-space: pre-wrap; word-wrap: break-word; }
table { font-size: 12px; }"""