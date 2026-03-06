"""
crawler.py
----------
Advanced crawler with Playwright network interception to discover API endpoints.
"""

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List, Dict, Optional, Tuple
import aiohttp
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Optional imports
try:
    from bs4 import BeautifulSoup
    BS_AVAILABLE = True
except ImportError:
    BS_AVAILABLE = False

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class Parameter:
    """Represents a discovered input parameter."""
    name: str
    location: str  # 'query', 'form', 'header', 'cookie', 'json', 'path'
    method: str     # 'GET', 'POST', 'HEADER', 'COOKIE'
    url: str        # Base URL where parameter was found
    original_value: Optional[str] = None  # For path parameters, the original value
    path_index: Optional[int] = None      # Index in path segments for path parameters
    form_data: Optional[Dict] = None      # For POST forms, default values


@dataclass
class Form:
    """Represents an HTML form."""
    action: str
    method: str  # 'get' or 'post'
    inputs: List[Dict[str, str]]  # list of {'name':..., 'type':..., 'value':...}


@dataclass
class CrawlResult:
    """Result of a crawl."""
    urls: Set[str] = field(default_factory=set)
    forms: List[Form] = field(default_factory=list)
    parameters: List[Parameter] = field(default_factory=list)


class Crawler:
    """
    Recursive crawler with parameter extraction.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        max_depth: int = 3,
        max_urls: int = 100,
        use_js: bool = False,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
    ):
        self.session = session
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.use_js = use_js and PLAYWRIGHT_AVAILABLE
        self.headers = headers or {}
        self.cookies = cookies or {}

        self.result = CrawlResult()
        self.visited = set()
        self._semaphore = asyncio.Semaphore(10)

        if use_js and not PLAYWRIGHT_AVAILABLE:
            logger.warning("JS crawling requested but Playwright is not installed. Install with: pip install playwright && playwright install chromium")

    async def crawl(self) -> CrawlResult:
        """Start crawling from target URL."""
        logger.info(f"Crawling started for {self.target_url}")
        await self._crawl_recursive(self.target_url, depth=0)
        logger.info(f"Crawling finished. Found {len(self.result.urls)} URLs, {len(self.result.forms)} forms.")
        self._extract_parameters_from_urls()
        self._extract_path_parameters()
        logger.info(f"Extracted {len(self.result.parameters)} parameters.")
        return self.result

    async def _crawl_recursive(self, url: str, depth: int):
        if depth > self.max_depth or len(self.result.urls) >= self.max_urls:
            return
        if url in self.visited:
            return
        self.visited.add(url)
        self.result.urls.add(url)

        try:
            async with self.session.get(url, headers=self.headers, cookies=self.cookies, allow_redirects=True) as resp:
                if resp.status != 200:
                    return
                try:
                    html = await resp.text()
                except:
                    return

                # Extract links and forms from HTML
                links = self._extract_links(html, url)
                forms = self._extract_forms(html, url)
                self.result.forms.extend(forms)

                # If JS rendering is enabled, also get links and API endpoints from rendered page
                if self.use_js:
                    js_links, api_endpoints = await self._extract_links_js(url)
                    links.extend(js_links)
                    # Add API endpoints as potential URLs to crawl
                    for api_url in api_endpoints:
                        if self._same_domain(api_url) and api_url not in self.visited:
                            links.append(api_url)

                # Recurse into discovered links
                for link in links:
                    if link not in self.visited and len(self.result.urls) < self.max_urls:
                        await self._crawl_recursive(link, depth + 1)

        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML using BeautifulSoup or regex fallback."""
        links = set()
        if BS_AVAILABLE:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                for tag in soup.find_all(['a', 'link', 'area'], href=True):
                    href = tag['href']
                    if href and not href.startswith(('#', 'mailto:', 'javascript:', 'tel:', 'data:')):
                        full = urljoin(base_url, href)
                        if self._same_domain(full):
                            links.add(full)
                for tag in soup.find_all(['img', 'script', 'iframe'], src=True):
                    src = tag['src']
                    full = urljoin(base_url, src)
                    if self._same_domain(full):
                        links.add(full)
                for tag in soup.find_all('form', action=True):
                    action = tag['action']
                    full = urljoin(base_url, action)
                    if self._same_domain(full):
                        links.add(full)
            except Exception:
                pass
        if not links:
            # regex fallback
            for match in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.IGNORECASE):
                url = match.group(1)
                if url and not url.startswith(('#', 'mailto:', 'javascript:', 'tel:', 'data:')):
                    full = urljoin(base_url, url)
                    if self._same_domain(full):
                        links.add(full)
        return list(links)

    def _extract_forms(self, html: str, base_url: str) -> List[Form]:
        """Extract forms from HTML."""
        forms = []
        if BS_AVAILABLE:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                for form_tag in soup.find_all('form'):
                    action = form_tag.get('action', '')
                    method = form_tag.get('method', 'get').lower()
                    inputs = []
                    for inp in form_tag.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if name:
                            inp_type = inp.get('type', 'text')
                            value = inp.get('value', '')
                            inputs.append({'name': name, 'type': inp_type, 'value': value})
                    forms.append(Form(
                        action=urljoin(base_url, action),
                        method=method,
                        inputs=inputs
                    ))
            except Exception:
                pass
        else:
            # simple regex fallback
            for match in re.finditer(r'<form\s+[^>]*action=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE):
                action = match.group(1)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', html[match.end():], re.IGNORECASE)
                forms.append(Form(
                    action=urljoin(base_url, action),
                    method='get',
                    inputs=[{'name': n, 'type': 'text', 'value': ''} for n in inputs]
                ))
        return forms

    async def _extract_links_js(self, url: str) -> Tuple[List[str], List[str]]:
        """
        Use Playwright with network interception to extract links and API endpoints.
        Returns (list of page links, list of API endpoint URLs).
        """
        if not PLAYWRIGHT_AVAILABLE:
            logger.debug("Playwright is not available.")
            return [], []

        browser = None
        api_urls = set()
        page_urls = set()

        try:
            async with async_playwright() as p:
                logger.info(f"Launching Playwright for {url}")
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                # Set longer timeout
                page.set_default_timeout(60000)

                # Intercept network requests
                async def handle_request(route, request):
                    req_url = request.url
                    if self._same_domain(req_url):
                        api_urls.add(req_url)
                        logger.debug(f"Intercepted request: {request.method} {req_url}")
                    await route.continue_()

                await context.route("**/*", handle_request)

                # Navigate and wait for network idle
                logger.info(f"Navigating to {url} with Playwright")
                await page.goto(url, wait_until='networkidle', timeout=60000)

                # Give some extra time for any late requests
                await asyncio.sleep(2)

                # Get all links from <a> tags
                links = await page.eval_on_selector_all('a', 'elements => elements.map(a => a.href)')
                for link in links:
                    if self._same_domain(link):
                        page_urls.add(link)

                await context.close()
                await browser.close()
                logger.info(f"Playwright extracted {len(page_urls)} page links and {len(api_urls)} API endpoints")
                return list(page_urls), list(api_urls)

        except PlaywrightTimeoutError:
            logger.error(f"Playwright timeout for {url}")
            if browser:
                try:
                    await browser.close()
                except:
                    pass
            return [], []
        except Exception as e:
            logger.error(f"Playwright error for {url}: {e}")
            if browser:
                try:
                    await browser.close()
                except:
                    pass
            return [], []

    def _same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain as target."""
        try:
            target_netloc = urlparse(self.target_url).netloc
            url_netloc = urlparse(url).netloc
            return target_netloc == url_netloc
        except:
            return False

    def _extract_parameters_from_urls(self):
        """Extract query parameters from all discovered URLs."""
        for url in self.result.urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params.keys():
                self.result.parameters.append(Parameter(
                    name=param_name,
                    location='query',
                    method='GET',
                    url=url
                ))

        # Also add form parameters
        for form in self.result.forms:
            for inp in form.inputs:
                self.result.parameters.append(Parameter(
                    name=inp['name'],
                    location='form',
                    method=form.method.upper(),
                    url=form.action,
                    form_data={i['name']: i['value'] for i in form.inputs}
                ))

    def _extract_path_parameters(self):
        """
        Extract potential parameters from URL paths.
        Heuristics: numeric segments, UUID-like segments.
        """
        path_param_pattern = re.compile(r'^(\d+|[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12})$', re.IGNORECASE)
        for url in self.result.urls:
            parsed = urlparse(url)
            segments = parsed.path.split('/')
            for idx, seg in enumerate(segments):
                if path_param_pattern.match(seg):
                    param_name = f"path_param_{idx}"
                    self.result.parameters.append(Parameter(
                        name=param_name,
                        location='path',
                        method='GET',
                        url=url,
                        original_value=seg,
                        path_index=idx
                    ))