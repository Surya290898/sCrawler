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
    """
    Accept flattened headers where multiple Set-Cookie are joined with newline separators.
    Split and return as a list.
    """
    raw = headers.get("set-cookie", "") or ""
    if not raw:
        return []
    return [line.strip() for line in raw.split("\n") if line.strip()]

def _parse_hsts(value: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for token in value.split(";"):
        token = token.strip()
        if "=" in token:
            k, v = token.split("=", 1)
            result[k.strip().lower()] = v.strip()
        else:
            result[token.strip().lower()] = "true"
    return result

def _parse_cookie_line(line: str) -> Dict[str, str]:
    """
    Parse a single Set-Cookie header line into a dict of attributes.
    Keys are lowercased for attributes; 'name' and 'value' kept as identifiers.
    """
    parts = [p.strip() for p in line.split(";")]
    if not parts:
        return {}
    cookie: Dict[str, str] = {}
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

def _likely_directory_listing(page_title: str) -> bool:
    t = (page_title or "").strip().lower()
    if not t:
        return False
    # Common directory-index titles
    candidates = [
        "index of /", "directory listing for", "listing of /", "directory /",
        "index of", "directory listing"
    ]
    return any(c in t for c in candidates)

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
    page_title: str = "",  # NEW: used for directory-listing indicator
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
    summary: Dict[str, bool] = {
        "has_csp": False,
        "has_hsts": False,
        "has_xfo": False,
        "has_nosniff": False,
        "has_refpol": False,
        "has_permspol": False,
        "has_corp": False,
        "has_coep": False,
        "has_coop": False,
        "has_expect_ct": False,
        "has_set_cookie": False,
        "cors_wildcard": False,
    }

    # =========================
    # Transport Security / HSTS
    # =========================
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
    else:
        # HTTP page detected (not redirected). Treat as weaker enforcement signal.
        add_issue(
            "HTTP_UNENFORCED",
            "Page served over HTTP (no HTTPS enforcement observed)",
            _sev(2),  # MEDIUM
            "Content was retrieved over HTTP; users may be downgraded. Consider redirecting to HTTPS.",
            "Redirect HTTP to HTTPS site-wide and enable HSTS.",
            penalty=6
        )

    # ==========
    # CSP family
    # ==========
    csp = headers.get("content-security-policy")
    if not csp:
        add_issue(
            "CSP_MISSING",
            "Content-Security-Policy missing",
            _sev(1),  # HIGH
            "No CSP reduces XSS and injection resilience.",
            "Add a CSP, e.g., \"Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'\".",
            penalty=12
        )
    else:
        summary["has_csp"] = True
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

    # Clickjacking: XFO or CSP frame-ancestors
    xfo = (headers.get("x-frame-options") or "")
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
        # Potential conflict (info): legacy XFO + restrictive frame-ancestors with mismatch
        if xfo and fa_present and ("deny" in xfo.lower() or "sameorigin" in xfo.lower()):
            # not strictly wrong; just surface as info
            add_issue(
                "HEADER_OVERLAP_FRAME",
                "X-Frame-Options present alongside CSP frame-ancestors",
                _sev(4),  # INFO
                "Both X-Frame-Options and CSP frame-ancestors are set. Prefer frame-ancestors; XFO is legacy.",
                "Consider removing XFO once CSP frame-ancestors is fully deployed.",
                penalty=0
            )

    # MIME Sniffing
    xcto = (headers.get("x-content-type-options") or "")
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

    # Referrer-Policy
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

    # Permissions-Policy / Feature-Policy (deprecated)
    permspol = headers.get("permissions-policy")
    featurepol = headers.get("feature-policy")
    if not permspol and not featurepol:
        add_issue(
            "PERMSPOL_MISSING",
            "Permissions-Policy missing",
            _sev(3),  # LOW
            "Lack of restrictions on powerful browser features (camera, mic, geolocation).",
            "Add 'Permissions-Policy' to explicitly restrict features, e.g., 'geolocation=()'.",
            penalty=1
        )
    else:
        if permspol:
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
        if featurepol:
            add_issue(
                "FEATUREPOL_DEPRECATED",
                "Feature-Policy header is deprecated",
                _sev(4),  # INFO
                "Use 'Permissions-Policy' instead of 'Feature-Policy'.",
                "Migrate to 'Permissions-Policy'.",
                penalty=0
            )

    # Cross-Origin policies (CORP / COEP / COOP)
    corp = headers.get("cross-origin-resource-policy")
    coep = headers.get("cross-origin-embedder-policy")
    coop = headers.get("cross-origin-opener-policy")
    if corp:
        summary["has_corp"] = True
    else:
        add_issue(
            "CORP_MISSING",
            "Cross-Origin-Resource-Policy missing",
            _sev(3),  # LOW
            "Without CORP, some cross-origin resource protections are relaxed.",
            "Add 'Cross-Origin-Resource-Policy: same-origin' (or 'same-site' for broader use-cases).",
            penalty=1
        )
    if coep:
        summary["has_coep"] = True
    else:
        add_issue(
            "COEP_MISSING",
            "Cross-Origin-Embedder-Policy missing",
            _sev(3),  # LOW
            "COEP is required for powerful features like cross-origin isolation.",
            "Add 'Cross-Origin-Embedder-Policy: require-corp'.",
            penalty=1
        )
    if coop:
        summary["has_coop"] = True
    else:
        add_issue(
            "COOP_MISSING",
            "Cross-Origin-Opener-Policy missing",
            _sev(3),  # LOW
            "COOP helps isolate browsing contexts to prevent cross-origin interference.",
            "Add 'Cross-Origin-Opener-Policy: same-origin'.",
            penalty=1
        )

    # Expect-CT (largely deprecated but requested)
    expect_ct = headers.get("expect-ct")
    if expect_ct:
        summary["has_expect_ct"] = True
    else:
        add_issue(
            "EXPECT_CT_MISSING",
            "Expect-CT header missing (deprecated)",
            _sev(4),  # INFO
            "Expect-CT is deprecated and generally unnecessary; surfaced because it was requested.",
            "No action typically required; rely on HSTS and certificate transparency elsewhere.",
            penalty=0
        )

    # =========
    # CORS eval
    # =========
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    acam = (headers.get("access-control-allow-methods") or "").strip().lower()
    if acao:
        if acao == "*" and acac == "true":
            add_issue(
                "CORS_WILDCARD_CREDENTIALS",
                "CORS allows any origin with credentials",
                _sev(1),  # HIGH
                "Allowing any origin with credentials enables cross-site data exfiltration.",
                "When credentials are allowed, set ACAO to a specific origin, not '*'.",
                penalty=12
            )
            summary["cors_wildcard"] = True
        elif acao == "*":
            add_issue(
                "CORS_WILDCARD",
                "CORS allows any origin (*)",
                _sev(2),  # MEDIUM
                "Wildcard ACAO can expose responses to any website.",
                "Restrict ACAO to specific trusted origins.",
                penalty=5
            )
        if any(m in acam for m in ["delete", "put", "patch"]):
            add_issue(
                "CORS_BROAD_METHODS",
                "Broad CORS methods allowed",
                _sev(3),  # LOW
                f"Exposes methods in CORS preflight: {acam}",
                "Restrict allowed methods to those strictly needed.",
                penalty=2
            )

    # ==================
    # Cookies & Sessions
    # ==================
    set_cookies = _getall_set_cookie(headers)
    has_set_cookie = bool(set_cookies)
    summary["has_set_cookie"] = has_set_cookie

    for line in set_cookies:
        c = _parse_cookie_line(line)
        name = c.get("name", "<cookie>")
        is_secure = "secure" in c
        is_httponly = "httponly" in c
        samesite = (c.get("samesite") or "").lower()

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

    # ========================
    # Caching / Privacy checks
    # ========================
    cache_ctrl = (headers.get("cache-control") or "").lower()
    pragma = (headers.get("pragma") or "").lower()
    is_sensitive_page = has_password_form or _is_login_like_url(url)

    # Sensitive pages should not be cached
    if is_sensitive_page and is_html:
        if not (("no-store" in cache_ctrl) or ("no-cache" in cache_ctrl)):
            add_issue(
                "CACHE_SENSITIVE",
                "Sensitive page may be cached",
                _sev(2),  # MEDIUM
                "Login or credential-related pages should not be cached by browser or proxies.",
                "Set 'Cache-Control: no-store' (preferred) or at least 'no-cache' on sensitive endpoints.",
                penalty=6
            )

    # Any HTML page that sets cookies should not be publicly cacheable
    if is_html and has_set_cookie:
        if "public" in cache_ctrl or not cache_ctrl:
            add_issue(
                "CACHE_COOKIE_PUBLIC",
                "Page that sets cookies appears publicly cacheable",
                _sev(2),  # MEDIUM
                "Public caching of cookie-setting responses risks session leakage.",
                "Use 'Cache-Control: private, no-store' for user-specific pages.",
                penalty=6
            )

    # ====================================
    # Server / Framework information leaks
    # ====================================
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
        elif value:
            add_issue(
                "TECH_STACK_DISCLOSED",
                f"{hdr_name} discloses technology",
                _sev(3),  # LOW
                f"Header reveals stack details: {value}",
                "Avoid disclosing technology stack via response headers.",
                penalty=1
            )

    # ===========================
    # Deprecated / Legacy headers
    # ===========================
    x_xss = (headers.get("x-xss-protection") or "").strip()
    if x_xss:
        add_issue(
            "XXSS_DEPRECATED_PRESENT",
            "X-XSS-Protection header present (deprecated)",
            _sev(4),  # INFO
            f"Found X-XSS-Protection: {x_xss}. Modern browsers ignore it; rely on CSP instead.",
            "Remove X-XSS-Protection and implement a robust CSP.",
            penalty=0
        )
    else:
        # The user explicitly asked to track "Missing X-XSS-Protection".
        add_issue(
            "XXSS_DEPRECATED_MISSING",
            "X-XSS-Protection header missing (deprecated)",
            _sev(4),  # INFO
            "This header is deprecated and generally unnecessary today.",
            "No action typically required; ensure strong CSP instead.",
            penalty=0
        )

    # =========================
    # Light content indicators
    # =========================
    if _likely_directory_listing(page_title):
        add_issue(
            "DIR_LISTING_INDICATOR",
            "Possible directory listing",
            _sev(2),  # MEDIUM
            f"Page title suggests directory listing: \"{page_title}\".",
            "Disable directory indexes or restrict access.",
            penalty=6
        )

    # Final clamp & return
    score = max(0, min(100, score))
    return score, issues, summary
