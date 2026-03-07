# crawler/jscloud_crawl.py
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

    - Executes JS in a real browser managed by Browserless.
    - Optionally clicks a few selectors (same-origin) to discover SPA routes.
    - Returns rendered HTML + response headers via /function endpoint.
      (We package code that navigates, listens for document responses, performs safe clicks, and returns content.)
    - Passive header audit only; no payloads/exploitation.

    Notes:
      * Endpoint must be something like 'https://production-sfo.browserless.io'.
      * An API token is required (?token=...).
      * Each call is stateless; we navigate and click within a single function request.
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
        http_auth: tuple[str, str] | None = None,  # (user, pass) for basic auth
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
        self.click_selectors = click_selectors or []  # e.g., ["a[role=button]", "button", "[role=button]"]
        self.max_clicks_per_page = max(0, max_clicks_per_page)
        self.goto_wait_until = goto_wait_until
        self.extra_headers = extra_headers or {}
        self.http_auth = http_auth

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
        self.last_error = None  # reset
        sem = asyncio.Semaphore(self.concurrency)

        # Basic session with timeouts
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=20, sock_read=60)
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers, trust_env=True) as session:
            # wave scheduler
            queue: Deque[Tuple[str, int]] = deque()

            if should_enqueue(self.start_url, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes):
                queue.append((self.start_url, 0))

            # convenient function endpoint url
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
                    # swallow per-wave errors; last_error is set per-task if fatal
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

            payload = self._build_function_payload(url)
            try:
                async with session.post(func_url, json=payload) as resp:
                    # Browserless /function returns JSON (return value of our function)
                    if resp.status >= 400:
                        self.last_error = f"/function HTTP {resp.status}"
                        return
                    data = await resp.json(content_type=None)  # allow application/json
            except Exception as e:
                self.last_error = f"/function call failed: {type(e).__name__}"
                return

            # expected data: { "html": "...", "finalUrl": "...", "status": int, "headers": {...} }
            html: str = data.get("html") or ""
            final_url: str = data.get("finalUrl") or url
            status: int = int(data.get("status") or 0)
            hdrs: Dict[str, str] = data.get("headers") or {}
            ctype = hdrs.get("content-type", "") or hdrs.get("Content-Type", "")
            scheme = URL(final_url).scheme

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

            # Header audit (passive)
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
                # keep crawling
                pass

    def _build_function_payload(self, url: str) -> Dict[str, Any]:
        """
        Build a /function payload that:
          - navigates to URL (waitUntil configurable),
          - records last 'document' response for headers+status,
          - optionally clicks a handful of selectors,
          - returns { html, finalUrl, status, headers }.
        Works with Browserless's /function REST API. (Playwright/Puppeteer supported by the backend)
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
              // capture last 'document' response (main resource) for headers+status
              if (req && typeof req.resourceType === 'function' && req.resourceType() === 'document') {
                mainResponse = res;
              }
            } catch (e) {}
          });

          await page.setExtraHTTPHeaders(context.extraHeaders || {});
          if (context.httpAuth && context.httpAuth.username) {
            await (page.context && page.context().setHTTPCredentials
              ? page.context().setHTTPCredentials(context.httpAuth)
              : null);
          }

          await page.goto(context.url, gotoOpts).catch(()=>{});

          // Try limited safe-click exploration for SPA routes
          let clicked = 0;
          for (const sel of selectors) {
            if (clicked >= maxClicks) break;
            try {
              const handles = await page.$$(sel);
              for (let i = 0; i < handles.length && clicked < maxClicks; i++) {
                try {
                  await handles[i].click({ delay: 20 }).catch(()=>{});
                  // let client-side routing settle
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
              // Puppeteer: headers(); Playwright via allHeaders()
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
