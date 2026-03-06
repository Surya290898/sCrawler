# crawler/browser_crawl.py
import asyncio
import random
from collections import deque
from typing import Deque, List, Set, Tuple, Optional

from bs4 import BeautifulSoup
from yarl import URL

from .utils import normalize_url, should_enqueue, is_within_scope_host
from .security_audit import analyze_headers
from .report import PageFinding, Issue

# Playwright is optional. Import guarded so the app can run without it.
try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    _PLAYWRIGHT_AVAILABLE = True
except Exception:
    BrowserContext = None  # type: ignore[assignment]
    Page = None            # type: ignore[assignment]
    _PLAYWRIGHT_AVAILABLE = False


DEFAULT_UA = "Crawler-For-Authorized-Assessment/1.0 (+https://example.com) JSClient"


class BrowserCrawler:
    """
    JavaScript-capable crawler using Playwright (Chromium headless).

    - Executes JS (SPA-friendly)
    - Parses rendered DOM for anchors
    - Optional "safe clicks" on same-origin buttons/links (client-side routes)
    - Passive header audit only (no payloads)

    This crawler sets `self.last_error` if Chromium/Context cannot start so the
    caller (app.py) can auto-fallback to HTTP mode gracefully.
    """

    def __init__(
        self,
        start_url: str,
        allow_subdomains: bool = True,
        max_depth: int = 3,
        max_pages: int = 500,
        concurrency: int = 3,  # JS pages are heavier; keep lower than HTTP mode
        rate_delay_range: tuple[float, float] = (0.1, 0.4),
        user_agent: str = DEFAULT_UA,
        exclude_prefixes: list[str] | None = None,
        cookie_string: str | None = None,
        basic_user: str | None = None,
        basic_pass: str | None = None,
        enable_safe_clicks: bool = False,
        max_clicks_per_page: int = 0,
    ):
        self.start_url = start_url
        self.allow_subdomains = allow_subdomains
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, concurrency)
        self.rate_delay_range = rate_delay_range
        self.user_agent = user_agent
        self.exclude_prefixes = exclude_prefixes or []
        self.cookie_string = cookie_string
        self.basic_user = basic_user
        self.basic_pass = basic_pass
        self.enable_safe_clicks = enable_safe_clicks
        self.max_clicks_per_page = max(0, max_clicks_per_page)

        self.findings: List[PageFinding] = []
        self.issues: List[Issue] = []
        self.visited: Set[str] = set()

        self.scope: Set[str] = set()
        self.scope_token: Optional[str] = None
        self._init_scope()

        # Will contain a short string on launch/context failures; None on success.
        self.last_error: Optional[str] = None

    def _init_scope(self):
        host = URL(self.start_url).host or ""
        if not self.allow_subdomains:
            self.scope = {host}
        else:
            from tldextract import extract
            ext = extract(host)
            token = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            self.scope = {token}
            self.scope_token = token

    async def run(self):
        """Run the JS crawler; set self.last_error on any startup failure."""
        # default = no error
        self.last_error = None

        if not _PLAYWRIGHT_AVAILABLE:
            self.last_error = "Playwright library not available"
            return

        sem = asyncio.Semaphore(self.concurrency)

        try:
            # Lazy import inside run for extra safety
            from playwright.async_api import async_playwright  # type: ignore
            async with async_playwright() as p:
                # ---- Launch Chromium (guarded) ----
                try:
                    browser = await p.chromium.launch(headless=True)
                except Exception as e:
                    # Most common on managed hosts without Chromium/OS deps
                    self.last_error = f"Chromium launch failed: {type(e).__name__}"
                    return

                # ---- Create context (guarded) ----
                context_args = dict(
                    user_agent=self.user_agent,
                    ignore_https_errors=True,
                    java_script_enabled=True,
                    viewport={"width": 1366, "height": 882},
                )
                if self.basic_user and self.basic_pass:
                    context_args["http_credentials"] = {
                        "username": self.basic_user,
                        "password": self.basic_pass,
                    }
                extra_headers = {}
                if self.cookie_string:
                    extra_headers["Cookie"] = self.cookie_string
                if extra_headers:
                    context_args["extra_http_headers"] = extra_headers

                try:
                    context: BrowserContext = await browser.new_context(**context_args)  # type: ignore[assignment]
                except Exception as e:
                    self.last_error = f"Context init failed: {type(e).__name__}"
                    try:
                        await browser.close()
                    except Exception:
                        pass
                    return

                # ---- Wave scheduler (like HTTP mode) ----
                queue: Deque[Tuple[str, int]] = deque()
                if should_enqueue(self.start_url, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes):
                    queue.append((self.start_url, 0))

                while queue and len(self.visited) < self.max_pages:
                    tasks = []
                    for _ in range(min(self.concurrency, len(queue))):
                        url, depth = queue.popleft()
                        if url in self.visited:
                            continue
                        self.visited.add(url)
                        tasks.append(asyncio.create_task(self._visit_one(context, url, depth, queue, sem)))

                    if not tasks:
                        break

                    try:
                        await asyncio.gather(*tasks)
                    except Exception:
                        # Swallow page-level errors; keep crawling.
                        pass

                # ---- Cleanup ----
                try:
                    await context.close()
                except Exception:
                    pass
                try:
                    await browser.close()
                except Exception:
                    pass

        except Exception as e:
            # Top-level unexpected error; signal to caller for fallback
            self.last_error = f"Playwright run failed: {type(e).__name__}"
            return

    async def _visit_one(
        self,
        context: BrowserContext,
        url: str,
        depth: int,
        queue: Deque[Tuple[str, int]],
        sem: asyncio.Semaphore
    ):
        async with sem:
            # Politeness delay
            await asyncio.sleep(random.uniform(*self.rate_delay_range))

            # Open a new page for isolation
            page: Page = await context.new_page()  # type: ignore[assignment]

            # Navigate and allow SPA bootstrap
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)

            # Collect response metadata
            headers = {}
            status = 0
            reason = ""
            if resp:
                try:
                    headers = await resp.all_headers()
                except Exception:
                    headers = (resp.headers or {}).copy()
                status = resp.status or 0
                reason = resp.status_text or ""

            final_url = page.url
            scheme = URL(final_url).scheme
            ctype = headers.get("content-type", "") or headers.get("Content-Type", "")
            clen = int(headers.get("content-length", "0") or 0)
            is_html = isinstance(ctype, str) and ("text/html" in ctype.lower()) and status < 400

            title = ""
            out_int = 0
            out_ext = 0
            forms = 0
            has_pwd = False
            pwd_over_http = (URL(final_url).scheme == "http")

            # Parse rendered DOM for anchors/forms
            if is_html:
                try:
                    html = await page.content()
                    soup = BeautifulSoup(html, "html.parser")
                    ttag = soup.find("title")
                    title = (ttag.text.strip() if ttag else "")[:200]

                    # Anchors (JS-rendered included)
                    links = [a.get("href") for a in soup.find_all("a", href=True)]
                    next_urls: List[str] = []
                    for href in links:
                        nu = normalize_url(final_url, href)
                        if not nu:
                            continue
                        if is_within_scope_host(nu, self.scope, self.allow_subdomains, start_url=self.start_url):
                            out_int += 1
                        else:
                            out_ext += 1
                        next_urls.append(nu)

                    # Forms/password detection
                    for form in soup.find_all("form"):
                        forms += 1
                        inputs = form.find_all("input")
                        if any((i.get("type") or "").lower() == "password" for i in inputs):
                            has_pwd = True

                    # Optional exploratory clicks (same-origin only)
                    if self.enable_safe_clicks and self.max_clicks_per_page > 0 and depth < self.max_depth:
                        selectors = [
                            "a[role='button']",
                            "button",
                            "[role='button']",
                            "a[href]"
                        ]
                        clicked = 0
                        for sel in selectors:
                            if clicked >= self.max_clicks_per_page:
                                break
                            try:
                                loc = page.locator(sel)
                                n = await loc.count()
                                for i in range(min(n, self.max_clicks_per_page - clicked)):
                                    before_url = page.url
                                    try:
                                        await loc.nth(i).scroll_into_view_if_needed(timeout=1000)
                                    except Exception:
                                        pass
                                    try:
                                        await loc.nth(i).click(timeout=2000)
                                        await page.wait_for_timeout(400)
                                    except Exception:
                                        continue
                                    after_url = page.url
                                    if after_url != before_url:
                                        nu = normalize_url(after_url, after_url)
                                        if nu and is_within_scope_host(nu, self.scope, self.allow_subdomains, start_url=self.start_url):
                                            if nu not in self.visited and should_enqueue(
                                                nu, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes
                                            ):
                                                queue.append((nu, depth + 1))
                                                clicked += 1
                                    if clicked >= self.max_clicks_per_page:
                                        break
                            except Exception:
                                continue

                    # Enqueue discovered anchors
                    if depth < self.max_depth:
                        for nu in next_urls:
                            if nu not in self.visited and should_enqueue(
                                nu, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes
                            ):
                                queue.append((nu, depth + 1))
                except Exception:
                    # Keep crawling even if parsing fails
                    pass

            # Passive header audit
            try:
                lc = {k.lower(): v for k, v in (headers or {}).items()}
                page_score, sec_issues, _summary = analyze_headers(
                    url=final_url,
                    status=status,
                    headers_in=headers,
                    scheme=scheme,
                    is_html=is_html,
                    has_password_form=has_pwd,
                    page_title=title,
                )
                for si in sec_issues:
                    self.issues.append(Issue(
                        url=si.url,
                        check_id=si.check_id,
                        title=si.title,
                        severity=si.severity,
                        description=si.description,
                        recommendation=si.recommendation
                    ))
                self.findings.append(PageFinding(
                    url=url,
                    final_url=final_url,
                    status=status,
                    reason=reason,
                    title=title,
                    content_type=headers.get("content-type", "") or headers.get("Content-Type", ""),
                    content_length=clen,
                    scheme=scheme,
                    num_outlinks_internal=out_int,
                    num_outlinks_external=out_ext,
                    forms_count=forms,
                    has_password_form=has_pwd,
                    password_form_over_http=pwd_over_http,
                    hdr_csp=("content-security-policy" in lc),
                    hdr_xfo=("x-frame-options" in lc),
                    hdr_hsts=("strict-transport-security" in lc),
                    hdr_xcto=("x-content-type-options" in lc),
                    hdr_refpol=("referrer-policy" in lc),
                    security_score=page_score
                ))
            except Exception:
                pass

            # Close page
            try:
                await page.close()
            except Exception:
                pass
