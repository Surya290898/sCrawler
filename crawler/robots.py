import asyncio
from urllib.parse import urlparse, urljoin
from urllib import robotparser
import aiohttp
from xml.etree import ElementTree

async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int = 15) -> str | None:
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status == 200:
                return await resp.text()
    except Exception:
        return None
    return None

async def load_robots(session: aiohttp.ClientSession, base_url: str, user_agent: str) -> tuple[robotparser.RobotFileParser | None, list[str]]:
    """
    Returns (robotparser or None if not found, sitemap_urls list)
    """
    parts = urlparse(base_url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
    txt = await fetch_text(session, robots_url)
    sitemaps = []
    rp = None
    if txt:
        rp = robotparser.RobotFileParser()
        rp.parse(txt.splitlines())
        # Extract sitemaps if present
        for line in txt.splitlines():
            if line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    sitemaps.append(sm)
    else:
        rp = None
    # Also try /sitemap.xml if not present
    if not sitemaps:
        sitemap_url = urljoin(f"{parts.scheme}://{parts.netloc}", "/sitemap.xml")
        text = await fetch_text(session, sitemap_url)
        if text and "<urlset" in text or "<sitemapindex" in text:
            sitemaps.append(sitemap_url)
    return rp, sitemaps

def can_fetch(rp: robotparser.RobotFileParser | None, user_agent: str, url: str, respect: bool) -> bool:
    if not respect or rp is None:
        return True
    try:
        return rp.can_fetch(user_agent, url)
    except Exception:
        return True

def parse_sitemap(xml_text: str) -> list[str]:
    urls = []
    try:
        root = ElementTree.fromstring(xml_text)
        ns = {"s": root.tag[root.tag.find("{")+1:root.tag.find("}")]} if "}" in root.tag else {}
        # urlset
        for u in root.findall(".//s:url/s:loc", ns) + root.findall(".//url/loc"):
            if u.text:
                urls.append(u.text.strip())
        # sitemapindex -> nested sitemaps
        for sm in root.findall(".//s:sitemap/s:loc", ns) + root.findall(".//sitemap/loc"):
            if sm.text:
                urls.append(sm.text.strip())
    except Exception:
        pass
    return urls
