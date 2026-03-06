#!/usr/bin/env python3
"""
VA Scanner – Main Entry Point with Progress Indicators and Speed Options
"""
import asyncio
import argparse
import logging
import sys
from datetime import datetime

import aiohttp

# Import scanner modules
from scanner.crawler import Crawler
from scanner.detector import (
    SQLiDetector, XSSDetector, LfiDetector, SsrfDetector,
    CmdInjectDetector, OpenRedirectDetector
)
from scanner.verification_engine import VerificationEngine
from scanner.evidence_collector import EvidenceCollector
from scanner.report_generator import ProfessionalReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('scanner.log')
    ]
)
logger = logging.getLogger("vapt_scanner")

# Optional tqdm for progress bars
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    tqdm = lambda x, **kwargs: x  # dummy


async def main():
    parser = argparse.ArgumentParser(description="VA Scanner with Progress and Speed Control")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("--max-urls", type=int, default=100, help="Max URLs to crawl")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent requests")
    parser.add_argument("--js", action="store_true", help="Enable JS crawling (requires Playwright)")
    parser.add_argument("--output", "-o", default="report.html", help="Output HTML file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Speed control options
    parser.add_argument("--quick", action="store_true", help="Quick scan: max-urls=30, depth=2, no JS, limited payloads")
    parser.add_argument("--no-time-based", action="store_true", help="Skip time-based payloads (SLEEP, WAITFOR, etc.)")
    parser.add_argument("--payload-count", type=int, default=0, help="Maximum number of payloads per vulnerability type (0 = use all)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")

    args = parser.parse_args()

    # Adjust settings for quick scan
    if args.quick:
        args.max_urls = 30
        args.depth = 2
        args.js = False
        if args.payload_count == 0:
            args.payload_count = 5  # use only 5 payloads per type

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    start_time = datetime.now()
    logger.info(f"Starting scan on {args.target}")

    timeout = aiohttp.ClientTimeout(total=30)
    request_count = 0

    def increment_request():
        nonlocal request_count
        request_count += 1

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # --- Phase 1: Crawling ---
        logger.info("Phase 1: Crawling website...")
        crawler = Crawler(
            session, args.target,
            max_depth=args.depth,
            max_urls=args.max_urls,
            use_js=args.js
        )

        crawl_result = await crawler.crawl()
        logger.info(f"Crawling completed. Found {len(crawl_result.urls)} URLs, {len(crawl_result.forms)} forms, {len(crawl_result.parameters)} parameters.")

        # --- Phase 1.5: Technology Detection ---
        logger.info("Detecting technology stack...")
        tech_stack = {}
        for url in list(crawl_result.urls)[:5]:
            try:
                async with session.get(url) as resp:
                    server = resp.headers.get('Server', '')
                    powered = resp.headers.get('X-Powered-By', '')
                    if server:
                        tech_stack[server.split('/')[0]] = server
                    if powered:
                        tech_stack[powered.split('/')[0]] = powered
            except:
                pass

        # Print detected tech stack to terminal
        if tech_stack:
            print("\n🔍 Detected Technology Stack:")
            for name, version in tech_stack.items():
                print(f"   • {name}: {version}")
        else:
            print("\n🔍 Detected Technology Stack: None detected from HTTP headers")

        # --- Phase 2: Initial Detection ---
        logger.info("Phase 2: Running initial vulnerability detection...")
        detectors = [
            SQLiDetector(session, delay=args.delay, payload_count=args.payload_count,
                         no_time_based=args.no_time_based, request_counter=increment_request),
            XSSDetector(session, delay=args.delay, payload_count=args.payload_count,
                        request_counter=increment_request),
            LfiDetector(session, delay=args.delay, payload_count=args.payload_count,
                        request_counter=increment_request),
            SsrfDetector(session, delay=args.delay, payload_count=args.payload_count,
                         request_counter=increment_request),
            CmdInjectDetector(session, delay=args.delay, payload_count=args.payload_count,
                              no_time_based=args.no_time_based, request_counter=increment_request),
            OpenRedirectDetector(session, delay=args.delay, payload_count=args.payload_count,
                                 request_counter=increment_request),
        ]

        potential_vulns = []
        total_params = len(crawl_result.parameters)
        logger.info(f"Testing {total_params} parameters...")

        # Progress bar for parameter testing
        param_iter = tqdm(crawl_result.parameters, desc="Testing parameters", unit="param", disable=not TQDM_AVAILABLE)
        for param in param_iter:
            # For blind detection, we could fetch a baseline response, but we'll skip for now
            baseline = None
            for detector in detectors:
                try:
                    findings = await detector.detect(param.__dict__, baseline)
                    if findings:
                        potential_vulns.extend(findings)
                        if TQDM_AVAILABLE:
                            param_iter.set_postfix_str(f"Found {len(potential_vulns)} potential")
                except Exception as e:
                    if args.verbose:
                        logger.debug(f"Detector error on {param}: {e}")

        logger.info(f"Initial detection found {len(potential_vulns)} potential vulnerabilities.")

        # --- Phase 3: Verification ---
        logger.info("Phase 3: Verifying potential vulnerabilities...")
        evidence_collector = EvidenceCollector()
        verifier = VerificationEngine(session, evidence_collector)
        confirmed_vulns = []

        vuln_iter = tqdm(potential_vulns, desc="Verifying", unit="vuln", disable=not TQDM_AVAILABLE)
        for pv in vuln_iter:
            confirmed = await verifier.verify(pv)
            if confirmed:
                confirmed_vulns.append(confirmed)
                logger.warning(f"[{confirmed.severity}] Confirmed {confirmed.type} at {confirmed.url} (param: {confirmed.parameter})")
                if TQDM_AVAILABLE:
                    vuln_iter.set_postfix_str(f"Confirmed {len(confirmed_vulns)}")

        logger.info(f"Verification complete. {len(confirmed_vulns)} vulnerabilities confirmed.")

        # --- Phase 4: Reporting ---
        logger.info("Phase 4: Generating report...")
        vuln_dicts = []
        for conf in confirmed_vulns:
            ev = conf.evidence
            vuln_dicts.append({
                "type": conf.type,
                "title": conf.type,
                "url": conf.url,
                "parameter": conf.parameter,
                "payload": conf.payload,
                "severity": conf.severity,
                "cvss_score": conf.cvss,
                "cwe_id": conf.cwe,
                "owasp": conf.owasp,
                "description": conf.description,
                "evidence": [{
                    "request_url": ev.request_url,
                    "method": ev.request_method,
                    "parameter": conf.parameter,
                    "payload": conf.payload,
                    "response_status": ev.response_status,
                    "response_headers": ev.response_headers,
                    "response_body": ev.response_body[:500],
                }]
            })

        duration = (datetime.now() - start_time).total_seconds()
        report_gen = ProfessionalReportGenerator(args.target, duration)
        report_gen.generate_html_report(
            vulnerabilities=vuln_dicts,
            tech_stack=tech_stack,
            output_path=args.output,
            discovered_urls=list(crawl_result.urls),
            total_requests=request_count
        )

        logger.info(f"Report saved to {args.output}")
        print(f"\n✅ Scan completed in {duration:.2f} seconds.")
        print(f"   Total HTTP requests: {request_count}")
        print(f"   Confirmed vulnerabilities: {len(confirmed_vulns)}")
        print(f"   Report: {args.output}")

if __name__ == "__main__":
    asyncio.run(main())