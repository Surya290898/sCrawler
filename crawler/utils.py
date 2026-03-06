from urllib.parse import urljoin, urlparse, urlunparse, urldefrag
from yarl import URL
import tldextract

def normalize_url(base: str, href: str) -> str | None:
    """
    Normalize and resolve href relative to base.
    - Removes fragments
    - Lowercases scheme/host
    - Strips default ports
    """
    try:
        joined = urljoin(base, href)
        clean, _ = urldefrag(joined)  # drop #fragment
        parts = urlparse(clean)
        # reject non-http(s)
        if parts.scheme not in ("http", "https"):
            return None
        netloc = parts.hostname or ""
        if parts.port:
            # Keep port only if non-default
            if (parts.scheme == "http" and parts.port != 80) or (parts.scheme == "https" and parts.port != 443):
                netloc = f"{netloc}:{parts.port}"
        normalized = urlunparse((parts.scheme, netloc.lower(), parts.path or "/", parts.params, parts.query, ""))
        return normalized
    except Exception:
        return None

def same_registrable_domain(a: str, b: str) -> bool:
    ea = tldextract.extract(URL(a).host or "")
    eb = tldextract.extract(URL(b).host or "")
    da = f"{ea.domain}.{ea.suffix}" if ea.suffix else ea.domain
    db = f"{eb.domain}.{eb.suffix}" if eb.suffix else eb.domain
    return bool(da) and da == db

def is_allowed_host(url: str, allowed_hosts: set[str]) -> bool:
    host = URL(url).host
    if not host:
        return False
    return host in allowed_hosts

def canonical_host_set(root: str, allow_subdomains: bool) -> set[str]:
    """
    Build allowed host set based on root URL and flag for subdomains.
    """
    host = URL(root).host or ""
    if not allow_subdomains:
        return {host}
    # include subdomains based on registrable domain
    ext = tldextract.extract(host)
    reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    # we accept any host that ends with the registrable domain
    # host check is done via suffix check in is_within_scope_host()
    return {reg}

def is_within_scope_host(url: str, scope: set[str], allow_subdomains: bool) -> bool:
    host = URL(url).host or ""
    if not host:
        return False
    if not allow_subdomains:
        return host in scope
    # scope contains registrable domain token
    token = next(iter(scope))
    return host == token or host.endswith("." + token)

def should_enqueue(url: str, start_url: str, scope: set[str], allow_subdomains: bool, exclude_prefixes: list[str]) -> bool:
    if not is_within_scope_host(url, scope, allow_subdomains):
        return False
    for p in exclude_prefixes:
        if url.startswith(p):
            return False
    # Stay on same scheme family (http/https)
    s0 = URL(start_url).scheme
    s1 = URL(url).scheme
    if s0 in ("http", "https") and s1 in ("http", "https"):
        return True
    return False
``
