# crawler/jscloud_crawl.py
"""
JS Cloud Crawler (Browserless.io REST)

This crawler renders pages in a real headless browser hosted by Browserless,
optionally clicks a few elements to trigger SPA routing, extracts anchors from
the rendered DOM, and runs the same passive header audit as your HTTP crawler.

Workflow per page:
  1) POST /function (Browserless) with a small JS snippet:
       - goto(url, waitUntil)
       - (optional) click up to N selectors
       - return { html, finalUrl, status, headers }
  2) If the HTML is tiny or blocked => fallback to:
       - POST /content  (returns fully rendered HTML as text/html)
       - POST /unblock  (returns rendered HTML when basic protections exist)
  3) Parse rendered HTML, enqueue discovered anchors within scope
  4) Run analyze_headers (passive) and store findings/issues

References:
  - Browserless REST APIs overview (/function, /content, /unblock)  https://docs.browserless.io/rest-apis/intro
  - /content returns fully-rendered HTML (post-JS)                    https://docs.browserless.io/rest-apis/content
"""

import asyncio
import random
from collections import deque
from typing import Deque, List, Set, Tuple, Optional, Dict, Any

import aiohttp
from bs4 import BeautifulSoup
from yarl import URL

from .utils import normalize_url, should_enqueue, is_within_scope_host
from .security_audit import analyze_headers
from .report import PageFinding, Issue


DEFAULT_UA = "Crawler-For-Authorized-Assessment/1.0 (+https://example.com) JSCloudClient"


class JSCloudCrawler:
    """
    JavaScript-capable crawler using Browserless REST API (no Docker/VM on your side).

    Parameters
    ----------
    start_url : str
        Seed URL to start crawling from.
    endpoint : str
        Browserless endpoint (e.g., 'https://production-sfo.browserless.io').
    api_token : str
        Browserless API token (dashboard → API Access).
    allow_subdomains : bool
        Whether to consider subdomains in-scope.
    max_depth : int
        Maximum crawl depth from each seed.
    max_pages : int
        Maximum total pages per seed.
    concurrency : int
        Parallel pages to process (cloud browser is heavier; 2–6 recommended).
    rate_delay_range : (float, float)
        Randomized polite delay between requests/clicks.
    user_agent : str
        Effective UA for both HTTP client and Browserless session (extra header).
    exclude_prefixes : list[str]
        URL prefixes to skip (e.g., logout/admin).
    click_selectors : list[str]
        CSS selectors for safe clicks to trigger SPA routing (e.g., ["a[href^='/']", "button"]).
    max_clicks_per_page : int
        Number of clicks per page (0–3 is typical).
    goto_wait_until : str
        One of {"load", "domcontentloaded", "networkidle"}; 'networkidle' useful for SPAs.
    extra_headers : dict
        Extra headers sent via setExtraHTTPHeaders in the browser (e.g., Cookie/User-Agent).
    http_auth : tuple[str, str] | None
        Basic credentials (username, password) for HTTP auth if required.
    """

    def __init__(
        self,
        start_url: str,
        endpoint: str,
        api_token: str,
        allow_subdomains: bool = True,
        max_depth: int = 3,
        max_pages: int = 500,
        concurrency: int = 3,
        rate_delay_range: tuple[float, float] = (0.1, 0.4),
        user_agent: str = DEFAULT_UA,
        exclude_prefixes: list[str] | None = None,
        click_selectors: list[str] | None = None,
        max_clicks_per_page: int = 0,
        goto_wait_until: str = "networkidle",
        extra_headers: Dict[str, str] | None = None,
        http_auth: tuple[str, str] | None = None,
        min_html_len_for_ok: int = 4000,  # threshold to detect "empty/blocked" HTML
    ):
        self.start_url = start_url
        self.endpoint = endpoint.rstrip("/")
        self.api_token = api_token
        self.allow_subdomains = allow_subdomains
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, concurrency)
        self.rate_delay_range = rate_delay_range
        self.user_agent = (user_agent or DEFAULT_UA).strip()
        self.exclude_prefixes = exclude_prefixes or []
        self.click_selectors = (
            [s.strip() for s in (click_selectors or []) if s.strip()]
            or ["a[href^='/']"]  # default that works well for SPAs with real anchors
        )
        self.max_clicks_per_page = max(0, max_clicks_per_page)
        self.goto_wait_until = goto_wait_until
        self.extra_headers = dict(extra_headers or {})
        self.http_auth = http_auth
        self.min_html_len_for_ok = min_html_len_for_ok

        # ensure UA is in extra headers used by the cloud browser
        if self.user_agent and "User-Agent" not in self.extra_headers:
            self.extra_headers["User-Agent"] = self.user_agent

        self.findings: List[PageFinding] = []
        self.issues: List[Issue] = []
        self.visited: Set[str] = set()

        # scope token (registrable domain) for enqueue
        self.scope: Set[str] = set()
        self.scope_token: Optional[str] = None
        self._init_scope()

        # if JS cloud fails, set this and let caller fallback to HTTP-mode
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
        """Wave-scheduled crawl using Browserless REST calls."""
        self.last_error = None  # reset

        sem = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=20, sock_read=60)
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers, trust_env=True) as session:
            queue: Deque[Tuple[str, int]] = deque()

            if should_enqueue(self.start_url, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes):
                queue.append((self.start_url, 0))

            func_url = f"{self.endpoint}/function?token={self.api_token}"

            while queue and len(self.visited) < self.max_pages:
                tasks = []
                for _ in range(min(self.concurrency, len(queue))):
                    url, depth = queue.popleft()
                    if url in self.visited:
                        continue
                    self.visited.add(url)

                    tasks.append(asyncio.create_task(
                        self._visit_one(session, func_url, url, depth, queue, sem)
                    ))

                if not tasks:
                    break

                try:
                    await asyncio.gather(*tasks)
                except Exception:
                    # per-wave safety; any page-level errors should not halt the crawl
                    pass

    async def _visit_one(
        self,
        session: aiohttp.ClientSession,
        func_url: str,
        url: str,
        depth: int,
        queue: Deque[Tuple[str, int]],
        sem: asyncio.Semaphore
    ):
        async with sem:
            await asyncio.sleep(random.uniform(*self.rate_delay_range))

            # 1) Try /function first: navigate + optional clicks + return html+headers
            payload = self._build_function_payload(url)
            try:
                async with session.post(func_url, json=payload) as resp:
                    if resp.status >= 400:
                        self.last_error = f"/function HTTP {resp.status}"
                        data = {}
                    else:
                        data = await resp.json(content_type=None)
            except Exception as e:
                self.last_error = f"/function call failed: {type(e).__name__}"
                data = {}

            html: str = data.get("html") or ""
            final_url: str = data.get("finalUrl") or url
            status: int = int(data.get("status") or 0)
            hdrs: Dict[str, str] = data.get("headers") or {}
            ctype = hdrs.get("content-type", "") or hdrs.get("Content-Type", "")
            scheme = URL(final_url).scheme

            # 2) Fallbacks if content seems empty/blocked:
            #    Try /content first, then /unblock (as needed).
            if len(html) < self.min_html_len_for_ok or status == 0 or status >= 400:
                better = await self._fetch_content_fallback(session, final_url)
                if len((better.get("html") or "")) > len(html):
                    html = better["html"]
                    final_url = better["finalUrl"]
                    status = better["status"]
                    hdrs = better["headers"]
                    ctype = hdrs.get("content-type", "") or hdrs.get("Content-Type", "")

            if len(html) < self.min_html_len_for_ok:
                ub = await self._fetch_unblock_fallback(session, final_url)
                if len((ub.get("html") or "")) > len(html):
                    html = ub["html"]
                    final_url = ub["finalUrl"]
                    status = ub["status"]
                    hdrs = ub["headers"]
                    ctype = hdrs.get("content-type", "") or hdrs.get("Content-Type", "")

            # Parse rendered content
            title = ""
            out_int = 0
            out_ext = 0
            forms = 0
            has_pwd = False
            pwd_over_http = (URL(final_url).scheme == "http")

            is_html = isinstance(ctype, str) and ("text/html" in ctype.lower()) and status < 400
            if html and status < 400:
                try:
                    soup = BeautifulSoup(html, "html.parser")
                    ttag = soup.find("title")
                    title = (ttag.text.strip() if ttag else "")[:200]

                    # anchor discovery (post-JS render)
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

                    # forms/password detection
                    for form in soup.find_all("form"):
                        forms += 1
                        inputs = form.find_all("input")
                        if any((i.get("type") or "").lower() == "password" for i in inputs):
                            has_pwd = True

                    # enqueue discovered anchors
                    if depth < self.max_depth:
                        for nu in next_urls:
                            if nu not in self.visited and should_enqueue(
                                nu, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes
                            ):
                                queue.append((nu, depth + 1))
                except Exception:
                    # ignore parse issues
                    pass

            # 3) Passive header audit
            try:
                page_score, sec_issues, _summary = analyze_headers(
                    url=final_url,
                    status=status,
                    headers_in=hdrs,
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
                    reason="",
                    title=title,
                    content_type=ctype,
                    content_length=len(html or ""),
                    scheme=scheme,
                    num_outlinks_internal=out_int,
                    num_outlinks_external=out_ext,
                    forms_count=forms,
                    has_password_form=has_pwd,
                    password_form_over_http=pwd_over_http,
                    hdr_csp=("content-security-policy" in {k.lower(): v for k, v in hdrs.items()}),
                    hdr_xfo=("x-frame-options" in {k.lower(): v for k, v in hdrs.items()}),
                    hdr_hsts=("strict-transport-security" in {k.lower(): v for k, v in hdrs.items()}),
                    hdr_xcto=("x-content-type-options" in {k.lower(): v for k, v in hdrs.items()}),
                    hdr_refpol=("referrer-policy" in {k.lower(): v for k, v in hdrs.items()}),
                    security_score=page_score
                ))
            except Exception:
                # keep crawling even if one page fails to audit
                pass

    # -----------------------------
    # Browserless helpers
    # -----------------------------
    def _build_function_payload(self, url: str) -> Dict[str, Any]:
        """
        Build a /function payload that:
          - navigates to URL (waitUntil configurable),
          - records last 'document' response for headers+status,
          - optionally clicks a handful of selectors,
          - returns { html, finalUrl, status, headers }.
        """
        code = """
        async ({ page, context }) => {
          const waitUntil = context.waitUntil || 'networkidle';
          const maxClicks = Math.max(0, Number(context.maxClicks || 0));
          const selectors = Array.isArray(context.clickSelectors) ? context.clickSelectors : [];
          const gotoOpts = { waitUntil, timeout: 30000 };

          let mainResponse = null;
          page.on('response', (res) => {
            try {
              const req = res.request && res.request();
              if (req && typeof req.resourceType === 'function' && req.resourceType() === 'document') {
                mainResponse = res;
              }
            } catch (e) {}
          });

          // Extra headers and HTTP auth (if supported in this environment)
          try { await page.setExtraHTTPHeaders(context.extraHeaders || {}); } catch (e) {}
          if (context.httpAuth && context.httpAuth.username) {
            try {
              const ctx = page.context && page.context();
              if (ctx && ctx.setHTTPCredentials) await ctx.setHTTPCredentials(context.httpAuth);
            } catch (e) {}
          }

          // Navigate
          try { await page.goto(context.url, gotoOpts); } catch (e) {}

          // Limited safe-click exploration for SPA routes (same session)
          let clicked = 0;
          for (const sel of selectors) {
            if (clicked >= maxClicks) break;
            try {
              const handles = await page.$$(sel);
              for (let i = 0; i < handles.length && clicked < maxClicks; i++) {
                try {
                  await handles[i].click({ delay: 20 });
                  if (page.waitForLoadState) {
                    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(()=>{});
                  } else {
                    await page.waitForTimeout(400).catch(()=>{});
                  }
                  clicked++;
                } catch (e) {}
              }
            } catch (e) {}
          }

          const html = await page.content();
          const finalUrl = page.url();
          let status = 0;
          let headers = {};
          try {
            if (mainResponse) {
              status = (await mainResponse.status()) || 0;
              headers = (await (mainResponse.headers ? mainResponse.headers() : mainResponse.allHeaders())) || {};
            }
          } catch (e) {}

          return { html, finalUrl, status, headers };
        }
        """.strip()

        ctx: Dict[str, Any] = {
            "url": url,
            "waitUntil": self.goto_wait_until,
            "clickSelectors": self.click_selectors,
            "maxClicks": self.max_clicks_per_page,
            "extraHeaders": self.extra_headers,
        }
        if self.http_auth and len(self.http_auth) == 2:
            ctx["httpAuth"] = {"username": self.http_auth[0], "password": self.http_auth[1]}

        return {
            "code": code,
            "context": ctx,
        }

    async def _fetch_content_fallback(self, session: aiohttp.ClientSession, url: str) -> dict:
        """
        Fallback to Browserless /content:
          - returns fully rendered HTML (text/html) post-JS
          - good when /function returned tiny/blocked content
        """
        content_url = f"{self.endpoint}/content?token={self.api_token}"
        try:
            async with session.post(content_url, json={"url": url}) as resp:
                html = await resp.text()
                return {
                    "html": html or "",
                    "finalUrl": url,
                    "status": resp.status,
                    "headers": {"content-type": resp.headers.get("content-type", "")}
                }
        except Exception:
            return {"html": "", "finalUrl": url, "status": 0, "headers": {}}

    async def _fetch_unblock_fallback(self, session: aiohttp.ClientSession, url: str) -> dict:
        """
        Optional fallback to Browserless /unblock (stealth-ish rendering):
          - useful for basic passive bot protections (e.g., cookie walls)
          - we request 'content: true' to receive rendered HTML in JSON
        """
        unblock_url = f"{self.endpoint}/unblock?token={self.api_token}"
        payload = {"url": url, "content": True}
        try:
            async with session.post(unblock_url, json=payload) as resp:
                # /unblock returns JSON; may contain { html, cookies, screenshot, ... }
                data = await resp.json(content_type=None)
                html = data.get("html") or ""
                return {
                    "html": html,
                    "finalUrl": data.get("url", url),
                    "status": 200 if html else 0,
                    "headers": {}
                }
        except Exception:
            return {"html": "", "finalUrl": url, "status": 0, "headers": {}}
