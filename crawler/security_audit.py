from dataclasses import dataclass
from typing import List, Dict, Tuple
import re
from urllib.parse import urlparse

# ---------------------------
# Severity & Issue Model
# ---------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

@dataclass
class SecurityIssue:
    url: str
    check_id: str
    title: str
    severity: str  # one of SEVERITY_ORDER
    description: str
    recommendation: str

def _sev(index: int) -> str:
    return SEVERITY_ORDER[index]

# ---------------------------
# Helpers
# ---------------------------

def _lc_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Case-insensitive dict (lowercase keys)."""
    return {k.lower(): v for k, v in headers.items() if isinstance(k, str)}

def _getall_set_cookie(headers: Dict[str, str]) -> List[str]:
    # In crawl.py we will pass merged headers where multiple Set-Cookie are joined with \n
    raw = headers.get("set-cookie", "") or ""
    if not raw:
        return []
    return [line.strip() for line in raw.split("\n") if line.strip()]

def _parse_directives(header_value: str) -> Dict[str, str]:
    out = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        if " " in part:
            k, v = part.split(" ", 1)
            out[k.strip().lower()] = v.strip()
        else:
            out[part.strip().lower()] = ""
    return out

def _parse_hsts(value: str) -> Dict[str, str]:
    result = {}
    for token in value.split(";"):
        token = token.strip()
        if "=" in token:
            k, v = token.split("=", 1)
            result[k.strip().lower()] = v.strip()
        else:
            result[token.strip().lower()] = "true"
    return result

def _parse_cookie_line(line: str) -> Dict[str, str]:
    parts = [p.strip() for p in line.split(";")]
    if not parts:
        return {}
    cookie = {}
    name_val = parts[0]
    if "=" in name_val:
        n, v = name_val.split("=", 1)
        cookie["name"] = n.strip()
        cookie["value"] = v.strip()
    else:
        cookie["name"] = name_val
        cookie["value"] = ""
    for attr in parts[1:]:
        if "=" in attr:
            k, v = attr.split("=", 1)
            cookie[k.strip().lower()] = v.strip()
        else:
            cookie[attr.strip().lower()] = "true"
    return cookie

def _looks_versioned(value: str) -> bool:
    # e.g., "Apache/2.4.54 (Ubuntu)" or "PHP/8.2.1"
    return bool(re.search(r"\d+\.\d+", value or ""))

def _is_login_like_url(url: str) -> bool:
    p = urlparse(url)
    path = (p.path or "").lower()
    qs = (p.query or "").lower()
    tokens = ["login", "signin", "auth", "account", "session"]
    return any(t in path or t in qs for t in tokens)

# ---------------------------
# Checks & Scoring
# ---------------------------

def analyze_headers(
    url: str,
    status: int,
    headers_in: Dict[str, str],
    scheme: str,
    is_html: bool,
    has_password_form: bool,
) -> Tuple[int, List[SecurityIssue], Dict[str, bool]]:
    """
    Returns (score, issues, summary_flags)
    - score: 0..100 (100 best)
    - issues: list of SecurityIssue
    - summary_flags: quick booleans for UI (e.g., has_csp, has_hsts, etc.)
    """
    headers = _lc_headers(headers_in)
    issues: List[SecurityIssue] = []
    score = 100

    def add_issue(check_id: str, title: str, sev: str, desc: str, rec: str, penalty: int):
        nonlocal score
        score = max(0, score - penalty)
        issues.append(SecurityIssue(url=url, check_id=check_id, title=title,
                                    severity=sev, description=desc, recommendation=rec))

    # Summary flags
    summary = {
        "has_csp": False,
        "has_hsts": False,
        "has_xfo": False,
        "has_nosniff": False,
        "has_refpol": False,
        "has_permspol": False,
        "has_set_cookie": False,
        "cors_wildcard": False,
    }

    # --- HSTS (HTTPS only) ---
    hsts = headers.get("strict-transport-security")
    if scheme == "https":
        if not hsts:
            add_issue(
                "HSTS_MISSING",
                "HSTS missing on HTTPS response",
                _sev(2),  # MEDIUM
                "The response is served over HTTPS but lacks Strict-Transport-Security header.",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS.",
                penalty=8
            )
        else:
            summary["has_hsts"] = True
            parsed = _parse_hsts(hsts)
            try:
                max_age = int(parsed.get("max-age", "0"))
            except ValueError:
                max_age = 0
            if max_age < 15552000:  # 180 days
                add_issue(
                    "HSTS_SHORT_MAXAGE",
                    "HSTS max-age too low",
                    _sev(2),  # MEDIUM
                    f"Configured HSTS max-age={max_age} is below recommended 15552000 (180 days).",
                    "Increase HSTS max-age to at least 15552000; consider 31536000 (1 year).",
                    penalty=4
                )
            if "includesubdomains" not in parsed:
                add_issue(
                    "HSTS_NO_SUBDOMAINS",
                    "HSTS missing includeSubDomains",
                    _sev(3),  # LOW
                    "HSTS does not include subdomains; subdomains may be downgraded to HTTP.",
                    "Add 'includeSubDomains' to HSTS for comprehensive protection.",
                    penalty=2
                )
    # If redirecting to HTTP
    if status in (301, 302, 303, 307, 308):
        loc = headers.get("location", "")
        if scheme == "https" and loc.lower().startswith("http://"):
            add_issue(
                "DOWNGRADE_REDIRECT",
                "HTTPS to HTTP redirect",
                _sev(1),  # HIGH
                f"Redirect sends users from HTTPS to HTTP: {loc}",
                "Avoid protocol downgrades; redirect to HTTPS equivalents only.",
                penalty=15
            )

    # --- CSP ---
    csp = headers.get("content-security-policy")
    if not csp:
        add_issue(
            "CSP_MISSING",
            "Content-Security-Policy missing",
            _sev(1),  # HIGH
            "No CSP reduces XSS and injection resilience.",
            "Add a CSP, e.g., 'Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self''.",
            penalty=12
        )
    else:
        summary["has_csp"] = True
        # Simple risk heuristics
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            add_issue(
                "CSP_UNSAFE",
                "CSP allows unsafe-inline or unsafe-eval",
                _sev(2),  # MEDIUM
                "Use of 'unsafe-inline' or 'unsafe-eval' weakens XSS protection.",
                "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for scripts/styles.",
                penalty=6
            )
        if "*" in csp_lower:
            add_issue(
                "CSP_WILDCARD",
                "CSP uses wildcard (*)",
                _sev(2),
                "Wildcard sources can allow untrusted origins.",
                "Restrict sources to explicit, trusted origins; avoid '*' where possible.",
                penalty=5
            )

    # --- Clickjacking: XFO or CSP frame-ancestors ---
    xfo = headers.get("x-frame-options")
    fa_present = ("frame-ancestors" in (csp.lower() if csp else ""))
    if not xfo and not fa_present:
        add_issue(
            "CLICKJACK_MISSING",
            "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
            _sev(1),  # HIGH
            "Pages may be embedded in hostile iframes (clickjacking).",
            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or set 'frame-ancestors' in CSP.",
            penalty=10
        )
    else:
        summary["has_xfo"] = bool(xfo)

    # --- MIME Sniffing ---
    xcto = headers.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        add_issue(
            "NOSNIFF_MISSING",
            "X-Content-Type-Options missing or not 'nosniff'",
            _sev(2),  # MEDIUM
            "Browsers may MIME-sniff and execute content in unsafe contexts.",
            "Add 'X-Content-Type-Options: nosniff'.",
            penalty=6
        )
    else:
        summary["has_nosniff"] = True

    # --- Referrer-Policy ---
    refpol = (headers.get("referrer-policy") or "").lower()
    if not refpol:
        add_issue(
            "REFPOL_MISSING",
            "Referrer-Policy missing",
            _sev(3),  # LOW
            "Browsers may send full referrer URLs to third-party sites.",
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' (balanced) or 'no-referrer' (most private).",
            penalty=2
        )
    else:
        summary["has_refpol"] = True
        if refpol in ("unsafe-url", "no-referrer-when-downgrade"):
            add_issue(
                "REFPOL_WEAK",
                f"Weak Referrer-Policy: {refpol}",
                _sev(3),
                "Policy may leak path/query to other origins.",
                "Prefer 'strict-origin-when-cross-origin' or 'no-referrer'.",
                penalty=2
            )

    # --- Permissions-Policy ---
    permspol = headers.get("permissions-policy") or headers.get("feature-policy")
    if not permspol:
        add_issue(
            "PERMSPOL_MISSING",
            "Permissions-Policy missing",
            _sev(3),  # LOW
            "Lack of restrictions on powerful browser features (camera, mic, geolocation).",
            "Add 'Permissions-Policy' to explicitly restrict features, e.g., 'geolocation=()'.",
            penalty=1
        )
    else:
        summary["has_permspol"] = True
        if "*" in permspol:
            add_issue(
                "PERMSPOL_WILDCARD",
                "Permissions-Policy uses wildcard (*)",
                _sev(3),
                "Wildcard may unintentionally allow features for all origins.",
                "Replace '*' with explicit allowlists or disable with '()'.",
                penalty=2
            )

    # --- Cookies ---
    set_cookies = _getall_set_cookie(headers)
    summary["has_set_cookie"] = bool(set_cookies)
    for line in set_cookies:
        c = _parse_cookie_line(line)
        name = c.get("name", "<cookie>")
        is_secure = "secure" in c
        is_httponly = "httponly" in c
        samesite = (c.get("samesite") or "").lower()

        # Cookie set over HTTP is risky
        if scheme == "http":
            add_issue(
                "COOKIE_OVER_HTTP",
                f"Cookie '{name}' set over HTTP",
                _sev(0),  # CRITICAL
                "Cookies set over HTTP can be intercepted and hijacked.",
                "Serve pages over HTTPS and set cookie with 'Secure; HttpOnly; SameSite=Lax/Strict'.",
                penalty=25
            )

        if not is_secure and scheme == "https":
            add_issue(
                "COOKIE_NO_SECURE",
                f"Cookie '{name}' missing 'Secure'",
                _sev(2),
                "Cookie may be sent over unsecured channels.",
                "Add 'Secure' attribute for cookies on HTTPS sites.",
                penalty=6
            )
        if not is_httponly:
            add_issue(
                "COOKIE_NO_HTTPONLY",
                f"Cookie '{name}' missing 'HttpOnly'",
                _sev(2),
                "Cookies accessible to JavaScript increase XSS impact.",
                "Add 'HttpOnly' to session/auth cookies.",
                penalty=6
            )
        if not samesite:
            add_issue(
                "COOKIE_NO_SAMESITE",
                f"Cookie '{name}' missing 'SameSite'",
                _sev(2),
                "Missing SameSite increases CSRF risk.",
                "Add 'SameSite=Lax' or 'SameSite=Strict'; if 'None', must include 'Secure'.",
                penalty=5
            )
        if samesite == "none" and not is_secure:
            add_issue(
                "COOKIE_NONE_NO_SECURE",
                f"Cookie '{name}' 'SameSite=None' without 'Secure'",
                _sev(1),
                "Cookies with SameSite=None must be marked Secure.",
                "Add 'Secure' attribute when using 'SameSite=None'.",
                penalty=10
            )

    # --- CORS ---
    acao = (headers.get("access-control-allow-origin") or "")
    acac = (headers.get("access-control-allow-credentials") or "").lower()
    if acao:
        if acao.strip() == "*" and acac == "true":
            add_issue(
                "CORS_WILDCARD_CREDENTIALS",
                "ACAO '*' with credentials",
                _sev(1),  # HIGH
                "Allowing any origin with credentials enables cross-site data exfiltration.",
                "When credentials are allowed, set ACAO to a specific origin, not '*'.",
                penalty=12
            )
            summary["cors_wildcard"] = True
        # Broad methods check
        acam = (headers.get("access-control-allow-methods") or "").lower()
        if any(m in acam for m in ["delete", "put", "patch"]):
            add_issue(
                "CORS_BROAD_METHODS",
                "Broad CORS methods allowed",
                _sev(3),  # LOW
                f"Exposes methods in CORS preflight: {acam}",
                "Restrict allowed methods to those strictly needed.",
                penalty=2
            )

    # --- Caching (sensitive contexts) ---
    cache_ctrl = (headers.get("cache-control") or "").lower()
    pragma = (headers.get("pragma") or "").lower()
    is_sensitive = has_password_form or _is_login_like_url(url)

    if is_sensitive and is_html:
        no_store = "no-store" in cache_ctrl
        no_cache = "no-cache" in cache_ctrl
        if not (no_store or no_cache):
            add_issue(
                "CACHE_SENSITIVE",
                "Sensitive page may be cached",
                _sev(2),  # MEDIUM
                "Login or credential-related pages should not be cached by browser or proxies.",
                "Set 'Cache-Control: no-store' (preferred) or at least 'no-cache' on sensitive endpoints.",
                penalty=6
            )

    # --- Server/Framework Disclosure ---
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    aspver = headers.get("x-aspnet-version", "")
    for hdr_name, value in [("Server", server), ("X-Powered-By", x_powered), ("X-AspNet-Version", aspver)]:
        if value and _looks_versioned(value):
            add_issue(
                "TECH_VERSION_DISCLOSED",
                f"{hdr_name} discloses version",
                _sev(3),  # LOW
                f"Header reveals software version: {value}",
                "Remove or generalize version-identifying headers to reduce targeted exploits.",
                penalty=2
            )

    # --- Deprecated Headers ---
    x_xss = (headers.get("x-xss-protection") or "").strip()
    if x_xss:
        # It's deprecated; if set to 0, note it's disabled
        add_issue(
            "XXSS_DEPRECATED",
            "X-XSS-Protection header is deprecated",
            _sev(4),  # INFO
            f"Found X-XSS-Protection: {x_xss}. Modern browsers ignore it; rely on CSP instead.",
            "Remove X-XSS-Protection and implement a robust CSP.",
            penalty=0
        )

    # Clamp score and return
    score = max(0, min(100, score))

    return score, issues, summary
``
