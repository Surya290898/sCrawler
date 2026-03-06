from urllib.parse import urljoin, urlparse, urlunparse, urldefrag
from yarl import URL
import tldextract
import re

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def _is_ip_host(host: str) -> bool:
    return bool(_IP_RE.match(host or ""))

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

def is_within_scope_host(url: str, scope: set[str], allow_subdomains: bool, start_url: str | None = None) -> bool:
    """
    Scope membership check that also handles IP/localhost cleanly.
    - If start_url is provided, always allow exact host match with the seed host.
    - If both hosts are IPs, require exact equality.
    - Otherwise, use registrable-domain logic with optional subdomains.
    """
    host = URL(url).host or ""
    if not host:
        return False

    seed_host = URL(start_url).host if start_url else None

    # Always allow exact seed host
    if seed_host and host == seed_host:
        return True

    # IP / localhost logic
    if _is_ip_host(host) or host in ("localhost",):
        if seed_host:
            return host == seed_host
        return False

    # Registrable-domain logic
    if not allow_subdomains:
        return host in scope

    token = next(iter(scope)) if scope else None  # registrable token (e.g., example.co.in)
    if not token:
        # fall back to equality
        return seed_host is not None and host == seed_host

    return host == token or host.endswith("." + token)

def should_enqueue(
    url: str,
    start_url: str,
    scope: set[str],
    allow_subdomains: bool,
    exclude_prefixes: list[str]
) -> bool:
    # Exclusions first
    for p in exclude_prefixes:
        if p and url.startswith(p):
            return False

    # Scope (with start_url assistance)
    if not is_within_scope_host(url, scope, allow_subdomains, start_url=start_url):
        return False

    # Stay on http/https
    s0 = URL(start_url).scheme
    s1 = URL(url).scheme
    return (s0 in ("http", "https")) and (s1 in ("http", "https"))
