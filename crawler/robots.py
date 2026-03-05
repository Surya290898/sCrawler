from urllib.parse import urlparse, urljoin
from urllib import robotparser
import aiohttp
from xml.etree import ElementTree

async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int = 15) -> str | None:
    """Fetch text content from a URL, returning None on errors or non-200 status."""
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            if resp.status == 200:
                # errors="ignore" avoids decode crashes on odd encodings
                return await resp.text(errors="ignore")
    except Exception:
        pass
    return None

async def load_robots(session: aiohttp.ClientSession, base_url: str, user_agent: str):
    """
    Load robots.txt (if present) and discover sitemap URLs.
    Returns: (robotparser or None, list_of_sitemaps)
    """
    parts = urlparse(base_url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"

    sitemaps: list[str] = []
    rp: robotparser.RobotFileParser | None = None

    txt = await fetch_text(session, robots_url)
    if txt:
        try:
            rp = robotparser.RobotFileParser()
            # Parse robots rules from content
            rp.parse(txt.splitlines())
        except Exception:
            rp = None

        # Extract "Sitemap:" entries from robots.txt
        for line in txt.splitlines():
            if line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    sitemaps.append(sm)

    # Fallback: try /sitemap.xml when none discovered via robots.txt
    if not sitemaps:
        sitemap_url = urljoin(f"{parts.scheme}://{parts.netloc}", "/sitemap.xml")
        text = await fetch_text(session, sitemap_url)
        # FIX: guard with parentheses and use real '<' tokens
        if text and ("<urlset" in text or "<sitemapindex" in text):
            sitemaps.append(sitemap_url)

    return rp, sitemaps

def can_fetch(rp: robotparser.RobotFileParser | None, user_agent: str, url: str, respect: bool) -> bool:
    """Check if a URL can be fetched according to robots.txt (if respecting robots)."""
    if not respect or rp is None:
        return True
    try:
        return rp.can_fetch(user_agent, url)
    except Exception:
        return True

def parse_sitemap(xml_text: str) -> list[str]:
    """
    Parse a sitemap XML (urlset or sitemapindex) and return discovered URLs.
    """
    urls: list[str] = []
    try:
        root = ElementTree.fromstring(xml_text)
        # Handle namespaced and non-namespaced XML
        ns = {"s": root.tag[root.tag.find("{")+1:root.tag.find("}")]} if "}" in root.tag else {}

        # urlset -> url -> loc
        for u in root.findall(".//s:url/s:loc", ns) + root.findall(".//url/loc"):
            if u.text:
                urls.append(u.text.strip())

        # sitemapindex -> sitemap -> loc (nested sitemaps)
        for sm in root.findall(".//s:sitemap/s:loc", ns) + root.findall(".//sitemap/loc"):
            if sm.text:
                urls.append(sm.text.strip())
    except Exception:
        pass

    return urls
