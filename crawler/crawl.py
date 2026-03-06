import asyncio
import random
from typing import Set, Deque, List
from collections import deque
from urllib.parse import urlparse
import aiohttp
from bs4 import BeautifulSoup
from yarl import URL

from .utils import normalize_url, should_enqueue, same_registrable_domain, is_within_scope_host
from .robots import load_robots, can_fetch, parse_sitemap, fetch_text
from .auth import AuthConfig, apply_cookie_header, perform_form_login, build_session_kwargs
from .report import PageFinding

DEFAULT_UA = "Crawler-For-Authorized-Assessment/1.0 (+https://example.com) StreamlitClient"

SEC_HEADERS = [
    ("Content-Security-Policy", "hdr_csp"),
    ("X-Frame-Options", "hdr_xfo"),
    ("Strict-Transport-Security", "hdr_hsts"),
    ("X-Content-Type-Options", "hdr_xcto"),
    ("Referrer-Policy", "hdr_refpol"),
]

class Crawler:
    def __init__(
        self,
        start_url: str,
        allow_subdomains: bool = True,
        max_depth: int = 3,
        max_pages: int = 500,
        concurrency: int = 8,
        respect_robots: bool = True,
        rate_delay_range: tuple[float, float] = (0.1, 0.5),
        user_agent: str = DEFAULT_UA,
        exclude_prefixes: list[str] | None = None,
        auth: AuthConfig | None = None,
    ):
        self.start_url = start_url
        self.allow_subdomains = allow_subdomains
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.respect_robots = respect_robots
        self.rate_delay_range = rate_delay_range
        self.user_agent = user_agent
        self.exclude_prefixes = exclude_prefixes or []
        self.auth = auth or AuthConfig()

        # scope host token(s)
        self.scope = set()
        self.scope_token = None  # registrable domain token if allow_subdomains
        self._init_scope()

        self.visited: Set[str] = set()
        self.findings: List[PageFinding] = []
        self.sem = asyncio.Semaphore(concurrency)

    def _init_scope(self):
        host = URL(self.start_url).host or ""
        if not self.allow_subdomains:
            self.scope = {host}
        else:
            # Store registrable domain token in scope, checked in utils
            from tldextract import extract
            ext = extract(host)
            token = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            self.scope = {token}
            self.scope_token = token

    async def run(self):
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        headers = apply_cookie_header(headers, self.auth.cookie_string)

        session_kwargs = build_session_kwargs(self.auth)
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(ssl=False, limit=0)  # let semaphore gate concurrency

        async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector, trust_env=True, raise_for_status=False) as session:
            # optional form login
            await perform_form_login(session, self.auth)

            rp, sitemaps = await load_robots(session, self.start_url, self.user_agent)

            # Seed URLs
            seeds = set([self.start_url])
            # parse sitemap(s) (limited)
            for sm in sitemaps[:5]:
                xml = await fetch_text(session, sm)
                if xml:
                    for u in parse_sitemap(xml):
                        nu = normalize_url(self.start_url, u)
                        if nu:
                            seeds.add(nu)

            # BFS crawl
            queue: Deque[tuple[str, int]] = deque()
            for s in seeds:
                if should_enqueue(s, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes):
                    queue.append((s, 0))

            while queue and len(self.visited) < self.max_pages:
                url, depth = queue.popleft()
                if url in self.visited:
                    continue
                self.visited.add(url)

                if not can_fetch(rp, self.user_agent, url, self.respect_robots):
                    continue

                await self.sem.acquire()
                asyncio.create_task(self._fetch_and_process(session, url, depth, queue))

            # Wait for all tasks to finish
            await self._drain()

    async def _drain(self):
        # Wait until semaphore is fully released (i.e., all tasks done)
        while self.sem._value != self.concurrency:  # type: ignore[attr-defined]
            await asyncio.sleep(0.05)

    async def _fetch_and_process(self, session: aiohttp.ClientSession, url: str, depth: int, queue):
        try:
            delay = random.uniform(*self.rate_delay_range)
            await asyncio.sleep(delay)
            async with session.get(url, allow_redirects=True) as resp:
                final_url = str(resp.url)
                status = resp.status
                reason = resp.reason or ""
                ctype = resp.headers.get("Content-Type", "")
                clen = int(resp.headers.get("Content-Length", "0") or 0)
                scheme = URL(final_url).scheme

                text = ""
                title = ""
                out_int = 0
                out_ext = 0
                forms = 0
                has_pwd = False
                pwd_over_http = False

                hdr_flags = {k: False for _, k in SEC_HEADERS}
                for h, key in SEC_HEADERS:
                    if resp.headers.get(h):
                        hdr_flags[key] = True

                # parse HTML for links/forms
                if "text/html" in ctype and status < 400:
                    try:
                        text = await resp.text(errors="ignore")
                        soup = BeautifulSoup(text, "lxml")
                        ttag = soup.find("title")
                        title = (ttag.text.strip() if ttag else "")[:200]

                        # links
                        links = [a.get("href") for a in soup.find_all("a", href=True)]
                        next_urls = []
                        for href in links:
                            nu = normalize_url(final_url, href)
                            if not nu:
                                continue
                            if is_within_scope_host(nu, self.scope, self.allow_subdomains):
                                out_int += 1
                            else:
                                out_ext += 1
                            next_urls.append(nu)

                        # forms
                        for form in soup.find_all("form"):
                            forms += 1
                            inputs = form.find_all("input")
                            if any((i.get("type") or "").lower() == "password" for i in inputs):
                                has_pwd = True
                                if URL(final_url).scheme == "http":
                                    pwd_over_http = True

                        # enqueue next
                        if depth < self.max_depth:
                            for u in next_urls:
                                if u not in self.visited and should_enqueue(u, self.start_url, self.scope, self.allow_subdomains, self.exclude_prefixes):
                                    # simple dedupe: push if not already planned
                                    queue.append((u, depth + 1))
                    except Exception:
                        pass

                self.findings.append(PageFinding(
                    url=url,
                    final_url=final_url,
                    status=status,
                    reason=reason,
                    title=title,
                    content_type=ctype,
                    content_length=clen,
                    scheme=scheme,
                    num_outlinks_internal=out_int,
                    num_outlinks_external=out_ext,
                    forms_count=forms,
                    has_password_form=has_pwd,
                    password_form_over_http=pwd_over_http,
                    hdr_csp=hdr_flags["hdr_csp"],
                    hdr_xfo=hdr_flags["hdr_xfo"],
                    hdr_hsts=hdr_flags["hdr_hsts"],
                    hdr_xcto=hdr_flags["hdr_xcto"],
                    hdr_refpol=hdr_flags["hdr_refpol"],
                ))
        except Exception:
            # swallow to continue
            pass
        finally:
            self.sem.release()
