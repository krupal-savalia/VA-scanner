# VA Scanner – Automated Web Vulnerability Scanner

A professional, modular web application vulnerability scanner designed for penetration testers and security researchers. It combines advanced crawling, intelligent payload injection, and a two‑stage verification process to deliver accurate results with minimal false positives.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

### Advanced Crawler
- **Recursive Discovery**: Automatically discovers URLs, forms, and parameters
- **Path Parameter Extraction**: Identifies testable inputs from URLs like `/product/123`
- **JavaScript Rendering**: Optional Playwright integration for SPA handling
- **Network Interception**: Captures API endpoints (XHR/fetch) for comprehensive coverage

### Comprehensive Vulnerability Detection
- **SQL Injection**: Error-based, boolean-based, and time-based detection
- **Cross-Site Scripting (XSS)**: Reflected and DOM-based XSS
- **Local File Inclusion (LFI) / Path Traversal**
- **Server-Side Request Forgery (SSRF)**
- **Command Injection**: Time-based and output-based detection
- **Open Redirect**
- Extensible architecture for additional vulnerability types

### Intelligent Payload Engine
- Multiple payload lists per vulnerability type
- Automatic payload mutations:
  - URL encoding
  - HTML entity encoding
  - Case variation
  - Comment insertion
- Configurable payload count for quick scans

### Two-Stage Verification
1. **Initial Detection**: Flags potential vulnerabilities with confidence scores
2. **Verification Stage**: Re-tests with precise payloads to eliminate false positives
3. **Confirmed Results**: Only verified vulnerabilities appear in the final report

### Professional HTML Report
- Executive summary with severity counts
- Vulnerability summary table (CVSS, CWE, OWASP, risk rating)
- Detailed findings with full HTTP request/response evidence
- Consolidated security recommendations
- Print-optimized CSS

### Performance Controls
- Concurrency and delay settings
- Quick-scan mode (limited URLs, depth, payloads)
- Option to skip time-based payloads for faster scans

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Install from Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vapt-scanner.git
cd vapt-scanner
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. (Optional) Install Playwright for JavaScript crawling:
```bash
playwright install chromium
```

## Usage

### Basic Scan
```bash
python main.py https://example.com
```

### Quick Scan (Faster, Fewer Payloads)
```bash
python main.py https://example.com --quick
```

### Full Scan with JavaScript Rendering
```bash
python main.py https://example.com --js --depth 5 --max-urls 200
```

### Skip Time-Based Payloads, Use Only 3 Payloads per Type
```bash
python main.py https://example.com --no-time-based --payload-count 3
```

### Stealthy Scan (Delay Between Requests)
```bash
python main.py https://example.com --delay 1 --concurrency 2
```

### Authenticated Scan (Provide Cookies)
```bash
python main.py https://example.com --cookie "sessionid=abc123"
```

### Save Report to Custom Location
```bash
python main.py https://example.com -o my-report.html
```

### Verbose Output (Debug Logging)
```bash
python main.py https://example.com --verbose
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `target` | Target URL to scan (required) |
| `--max-urls` | Maximum URLs to crawl (default: 100) |
| `--depth` | Crawl depth (default: 3) |
| `--concurrency` | Concurrent requests (default: 10) |
| `--js` | Enable JavaScript crawling (requires Playwright) |
| `--output`, `-o` | Output HTML report file (default: report.html) |
| `--verbose`, `-v` | Verbose output (debug logging) |
| `--quick` | Quick scan: max-urls=30, depth=2, no JS, payload-count=5 |
| `--no-time-based` | Skip time-based payloads (SLEEP, WAITFOR, etc.) |
| `--payload-count` | Maximum payloads per vulnerability type (0 = use all) |
| `--delay` | Delay between requests (seconds) |
| `--cookie` | Cookie string (e.g., "name=value; name2=value2") |
| `--header` | Additional headers (can be repeated) |

## Project Structure

```
vapt-scanner/
├── scanner/
│   ├── __init__.py
│   ├── crawler.py              # URL/parameter discovery
│   ├── payload_engine.py       # Payload definitions & mutations
│   ├── detector.py              # Initial vulnerability detection
│   ├── verification_engine.py  # Confirmation of vulnerabilities
│   ├── evidence_collector.py   # Evidence collection
│   └── report_generator.py     # HTML report generation
├── main.py                      # Entry point
├── requirements.txt            # Dependencies
└── README.md                    # This file
```

## How It Works

### 1. Crawling Phase
The crawler starts from the target URL and recursively follows same-domain links. It extracts:
- Query parameters from URLs
- Form inputs (GET/POST)
- Path parameters (numeric/UUID segments)
- (With `--js`) API endpoints via Playwright network interception

### 2. Parameter Discovery
All discovered input points are stored as `Parameter` objects with metadata:
- Location (query, form, header, cookie, json, path)
- HTTP method (GET, POST)
- Default values

### 3. Initial Detection
For each parameter, the scanner injects payloads from the PayloadEngine. Detectors look for immediate indicators:
- SQL errors for SQL Injection
- Reflected payloads for XSS
- File content for LFI
- Response differences for blind vulnerabilities

Returns `PotentialVulnerability` objects with confidence scores.

### 4. Verification Stage
Each potential vulnerability is re-tested with more precise methods:
- Boolean-based SQLi confirmation
- Time-based blind injection checks
- Payload reflection analysis

Only those that pass verification become `ConfirmedVulnerability`.

### 5. Reporting
Confirmed vulnerabilities are:
- Merged by type
- Sorted by severity
- Rendered into a professional HTML report with full request/response evidence

## Report Example

The generated report includes:

1. **Cover Page** - Target, date, tool version
2. **Executive Summary** - Severity counts and overall risk
3. **Scope & Methodology** - In-scope items and testing approach
4. **Scan Overview** - Metrics (URLs, requests, duration)
5. **Technology Stack** - Detected server/framework
6. **Vulnerability Summary Table** - Grouped by type with CVSS, CWE, OWASP
7. **Detailed Findings** - Each vulnerability with:
   - Affected endpoints
   - Vulnerable parameter
   - Payload used
   - Full HTTP request/response evidence
8. **Security Recommendations** - Tailored to detected vulnerability types
9. **Limitations & False Positive Handling** - Transparency about assessment constraints

## Configuration

### Custom Payloads

Edit `scanner/payload_engine.py` to add custom payloads:

```python
SQLI = [
    "'",
    '"',
    # Add your payloads here
]
```

### Adjusting Detection Sensitivity

Modify the detector classes in `scanner/detector.py` to adjust:
- Time-based thresholds
- Error pattern matching
- Confidence score thresholds

## Limitations

1. **JavaScript Crawling**: Requires Playwright and may not capture all dynamic content on complex SPAs.

2. **API Discovery**: JSON/GraphQL APIs are not yet automatically discovered or tested (planned for future releases).

3. **Authentication**: Limited to cookie passing; no automated login flows.

4. **False Negatives**: The scanner is not a substitute for manual penetration testing – always validate findings manually.

5. **Rate Limiting**: Some websites may block scanning attempts; adjust `--delay` and `--concurrency` settings accordingly.

## Security Notice

This tool is intended for authorized security testing only. Always ensure you have explicit permission before scanning any website. Unauthorized scanning is illegal and unethical.

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- OWASP Testing Guide
- Various open-source security tools that inspired this project

