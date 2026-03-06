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
        if not token:
            continue
        if "=" in token:
            k, v = token.split("=", 1)
            result[k.strip().lower()] = v.strip()
        else:
            result[token.strip().lower()] = "true"
    return result

def _hsts_duplicate_directives(raw: str) -> bool:
    """
    Detect duplicate directive *names* inside a single HSTS header value.
    """
    names: Dict[str, int] = {}
    for token in [t.strip() for t in raw.split(";") if t.strip()]:
        name = token.split("=", 1)[0].strip().lower()
        names[name] = names.get(name, 0) + 1
    return any(cnt > 1 for cnt in names.values())

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
    candidates = [
        "index of /", "directory listing for", "listing of /", "directory /",
        "index of", "directory listing"
    ]
    return any(c in t for c in candidates)

def _is_header_duplicated(value: str | None) -> bool:
    """
    Our fetch layer joins repeated header fields with '\\n'.
    If newline present => the header field appears multiple times.
    """
    if not value:
        return False
    return "\n" in value

def _parse_csp(raw: str) -> Tuple[Dict[str, str], bool]:
    """
    Parse CSP into {directive_name -> value_string}
    Return (dict, has_duplicate_names)
    """
    d: Dict[str, str] = {}
    seen: Dict[str, int] = {}
    for part in [p.strip() for p in raw.split(";") if p.strip()]:
        if " " in part:
            name, rest = part.split(" ", 1)
            name_l = name.lower()
            seen[name_l] = seen.get(name_l, 0) + 1
            # Keep first; we'll still report duplicates via 'seen'
            if name_l not in d:
                d[name_l] = rest.strip()
        else:
            name_l = part.lower()
            seen[name_l] = seen.get(name_l, 0) + 1
            if name_l not in d:
                d[name_l] = ""
    dup = any(cnt > 1 for cnt in seen.values())
    return d, dup

def _valid_acao_origin(value: str) -> bool:
    """
    ACAO must be '*' or 'null' or a single well-formed origin 'scheme://host[:port]' with no path/query/fragment.
    """
    if not value:
        return False
    v = value.strip()
    if v in ("*", "null"):
        return True
    # Disallow commas/spaces (server should vary by Origin, not return lists)
    if "," in v or " " in v:
        return False
    p = urlparse(v)
    if p.scheme not in ("http", "https"):
        return False
    if not p.netloc:
        return False
    if p.path or p.params or p.query or p.fragment:
        return False
    return True

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
    page_title: str = "",
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

    ineffective_names: List[str] = []

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
    hsts_raw = headers.get("strict-transport-security")
    if scheme == "https":
        if not hsts_raw:
            add_issue(
                "HSTS_MISSING",
                "Content-Security-Policy — Missing required headers" if False else "Strict-Transport-Security — Missing required headers",
                _sev(2),  # MEDIUM (BitSight classifies as required; we keep MEDIUM)
                "Strict-Transport-Security header is not present.",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS.",
                penalty=8
            )
        else:
            summary["has_hsts"] = True
            # Detect duplicated header fields (multiple HSTS lines)
            if _is_header_duplicated(hsts_raw):
                add_issue(
                    "HSTS_HEADER_DUPLICATED",
                    "Strict-Transport-Security — Header duplicated",
                    _sev(3),  # LOW
                    "Multiple Strict-Transport-Security headers were returned.",
                    "Return a single Strict-Transport-Security header per response.",
                    penalty=2
                )
            # Analyze directive values
            # If multiple header fields, join is with '\n'; analyze the first non-empty line for directives
            first_hsts = hsts_raw.split("\n")[0].strip()
            if first_hsts:
                if _hsts_duplicate_directives(first_hsts):
                    add_issue(
                        "HSTS_DUPLICATE_DIRECTIVE",
                        "Strict-Transport-Security — Directive used multiple times",
                        _sev(2),  # MEDIUM
                        "The HSTS policy repeats one or more directives, which can cause ambiguity.",
                        "Remove duplicate directives and keep a single value for each directive.",
                        penalty=4
                    )
                parsed = _parse_hsts(first_hsts)
                try:
                    max_age = int(parsed.get("max-age", "0"))
                except ValueError:
                    max_age = 0
                if max_age == 0 or max_age < 60:
                    add_issue(
                        "HSTS_EFFECTIVELY_DISABLED",
                        "Strict-Transport-Security — Ineffective header",
                        _sev(2),  # MEDIUM
                        f"HSTS max-age={max_age} disables or undermines enforcement.",
                        "Set a meaningful max-age (>= 15552000).",
                        penalty=6
                    )
                    ineffective_names.append("Strict-Transport-Security")
                if "includesubdomains" not in parsed:
                    add_issue(
                        "HSTS_NO_SUBDOMAINS",
                        "Strict-Transport-Security — Missing includeSubDomains",
                        _sev(3),  # LOW
                        "HSTS does not include subdomains; subdomains may be downgraded to HTTP.",
                        "Add 'includeSubDomains' to HSTS for comprehensive protection.",
                        penalty=2
                    )
    else:
        # HTTP page: HSTS (if present) is ignored by browsers; HTTPS not enforced
        if hsts_raw:
            add_issue(
                "HSTS_ON_HTTP_IGNORED",
                "Strict-Transport-Security — Ineffective header",
                _sev(3),  # LOW
                "HSTS served over HTTP is ignored by browsers.",
                "Redirect HTTP to HTTPS and serve HSTS only over HTTPS.",
                penalty=1
            )
            ineffective_names.append("Strict-Transport-Security")
        add_issue(
            "HTTP_UNENFORCED",
            "HTTP to HTTPS redirection missing",
            _sev(2),  # MEDIUM
            "Content was retrieved over HTTP; users may be downgraded.",
            "Redirect HTTP to HTTPS site-wide and enable HSTS.",
            penalty=6
        )

    # ==========
    # CSP family
    # ==========
    csp_raw = headers.get("content-security-policy")
    if not csp_raw:
        add_issue(
            "CSP_MISSING",
            "Content-Security-Policy — Missing required headers",
            _sev(1),  # HIGH
            "Content-Security-Policy header is not present.",
            "Add a CSP, e.g., \"Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'\".",
            penalty=12
        )
    else:
        summary["has_csp"] = True
        if _is_header_duplicated(csp_raw):
            add_issue(
                "CSP_HEADER_DUPLICATED",
                "Content-Security-Policy — Header duplicated",
                _sev(3),  # LOW
                "Multiple Content-Security-Policy headers were returned.",
                "Return a single Content-Security-Policy header per response.",
                penalty=2
            )
        csp_map, csp_dup = _parse_csp(csp_raw.split("\n")[0])
        if csp_dup:
            add_issue(
                "CSP_DUPLICATE_DIRECTIVE",
                "Content-Security-Policy — Directive used multiple times",
                _sev(2),  # MEDIUM
                "One or more CSP directives are repeated.",
                "Keep a single occurrence for each CSP directive.",
                penalty=4
            )
        csp_lower = csp_raw.lower()
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            add_issue(
                "CSP_UNSAFE",
                "Content-Security-Policy — Ineffective directives",
                _sev(2),  # MEDIUM
                "Use of 'unsafe-inline' or 'unsafe-eval' weakens XSS protection.",
                "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for scripts/styles.",
                penalty=6
            )
        if "*" in csp_lower:
            add_issue(
                "CSP_WILDCARD",
                "Content-Security-Policy — Ineffective directives",
                _sev(2),
                "Wildcard sources can allow untrusted origins.",
                "Restrict sources to explicit, trusted origins; avoid '*'.",
                penalty=5
            )

    # Clickjacking: XFO or CSP frame-ancestors
    xfo = (headers.get("x-frame-options") or "")
    fa_present = ("frame-ancestors" in (csp_raw.lower() if csp_raw else ""))
    if not xfo and not fa_present:
        add_issue(
            "CLICKJACK_MISSING",
            "X-Frame-Options — Missing required headers",
            _sev(1),  # HIGH
            "No clickjacking protection: X-Frame-Options or CSP frame-ancestors is missing.",
            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or set 'frame-ancestors' in CSP.",
            penalty=10
        )
    else:
        # presence is fine; no parity change needed
        pass

    # MIME Sniffing
    xcto = (headers.get("x-content-type-options") or "")
    if xcto.lower() != "nosniff":
        add_issue(
            "NOSNIFF_MISSING",
            "X-Content-Type-Options — Missing required headers",
            _sev(2),  # MEDIUM
            "X-Content-Type-Options header is missing or not 'nosniff'.",
            "Add 'X-Content-Type-Options: nosniff'.",
            penalty=6
        )

    # Referrer-Policy
    refpol = (headers.get("referrer-policy") or "").lower()
    if not refpol:
        add_issue(
            "REFPOL_MISSING",
            "Referrer-Policy — Missing required headers",
            _sev(3),  # LOW
            "Referrer-Policy header is not present.",
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' (balanced) or 'no-referrer' (most private).",
            penalty=2
        )
    elif refpol in ("unsafe-url", "no-referrer-when-downgrade"):
        add_issue(
            "REFPOL_WEAK",
            "Referrer-Policy — Ineffective header",
            _sev(3),  # LOW
            f"Weak Referrer-Policy: {refpol}",
            "Prefer 'strict-origin-when-cross-origin' or 'no-referrer'.",
            penalty=2
        )
        ineffective_names.append("Referrer-Policy")

    # Permissions-Policy / Feature-Policy (deprecated)
    permspol = headers.get("permissions-policy")
    featurepol = headers.get("feature-policy")
    if not permspol and not featurepol:
        add_issue(
            "PERMSPOL_MISSING",
            "Permissions-Policy — Missing required headers",
            _sev(3),  # LOW
            "Permissions-Policy is not present.",
            "Add 'Permissions-Policy' to explicitly restrict features, e.g., 'geolocation=()'.",
            penalty=1
        )
    else:
        if permspol and "*" in permspol:
            add_issue(
                "PERMSPOL_WILDCARD",
                "Permissions-Policy — Ineffective header",
                _sev(3),
                "Wildcard may unintentionally allow features for all origins.",
                "Replace '*' with explicit allowlists or disable with '()'.",
                penalty=2
            )
            ineffective_names.append("Permissions-Policy")
        if featurepol:
            add_issue(
                "FEATUREPOL_DEPRECATED",
                "Feature-Policy — Deprecated header",
                _sev(4),  # INFO
                "Feature-Policy is deprecated; use Permissions-Policy instead.",
                "Migrate to 'Permissions-Policy'.",
                penalty=0
            )

    # Cross-Origin policies (CORP / COEP / COOP)
    corp = headers.get("cross-origin-resource-policy")
    coep = headers.get("cross-origin-embedder-policy")
    coop = headers.get("cross-origin-opener-policy")
    if not corp:
        add_issue(
            "CORP_MISSING",
            "Cross-Origin-Resource-Policy — Missing header",
            _sev(3),  # LOW
            "CORP is not present.",
            "Add 'Cross-Origin-Resource-Policy: same-origin' (or 'same-site' as appropriate).",
            penalty=1
        )
    if not coep:
        add_issue(
            "COEP_MISSING",
            "Cross-Origin-Embedder-Policy — Missing header",
            _sev(3),  # LOW
            "COEP is not present.",
            "Add 'Cross-Origin-Embedder-Policy: require-corp'.",
            penalty=1
        )
    if not coop:
        add_issue(
            "COOP_MISSING",
            "Cross-Origin-Opener-Policy — Missing header",
            _sev(3),  # LOW
            "COOP is not present.",
            "Add 'Cross-Origin-Opener-Policy: same-origin'.",
            penalty=1
        )

    # Expect-CT (deprecated; parity INFO)
    expect_ct = headers.get("expect-ct")
    if not expect_ct:
        add_issue(
            "EXPECT_CT_MISSING",
            "Expect-CT — Missing header (deprecated)",
            _sev(4),  # INFO
            "Expect-CT is deprecated and generally unnecessary today.",
            "No action typically required; rely on HSTS and certificate transparency ecosystem.",
            penalty=0
        )

    # =========
    # CORS eval
    # =========
    acao_raw = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    acam = (headers.get("access-control-allow-methods") or "").strip().lower()

    if acao_raw:
        if _is_header_duplicated(acao_raw):
            add_issue(
                "ACAO_HEADER_DUPLICATED",
                "Access-Control-Allow-Origin — Header duplicated",
                _sev(3),  # LOW
                "Multiple Access-Control-Allow-Origin headers were returned.",
                "Return a single Access-Control-Allow-Origin header per response.",
                penalty=2
            )

        if acao_raw == "*" and acac == "true":
            add_issue(
                "CORS_WILDCARD_CREDENTIALS",
                "Access-Control-Allow-Origin — Ineffective header",
                _sev(1),  # HIGH
                "ACAO '*' with credentials enabled allows cross-site data exfiltration.",
                "When credentials are allowed, set ACAO to a specific origin, not '*'.",
                penalty=12
            )
            ineffective_names.append("Access-Control-Allow-Origin")
        elif acao_raw == "*":
            add_issue(
                "CORS_WILDCARD",
                "Access-Control-Allow-Origin — Broad policy",
                _sev(2),  # MEDIUM
                "Wildcard ACAO exposes responses to any website.",
                "Restrict ACAO to specific trusted origins.",
                penalty=5
            )

        # Parity: "Invalid URL"
        if not _valid_acao_origin(acao_raw):
            add_issue(
                "CORS_ACAO_INVALID_VALUE",
                "Access-Control-Allow-Origin — Invalid URL",
                _sev(2),  # MEDIUM
                f"ACAO value '{acao_raw}' is not a valid single origin or wildcard.",
                "Return a single origin like 'https://example.com' (or '*' with no credentials).",
                penalty=4
            )

        if any(m in acam for m in ["delete", "put", "patch"]):
            add_issue(
                "CORS_BROAD_METHODS",
                "Access-Control-Allow-Methods — Broad methods allowed",
                _sev(3),  # LOW
                f"Preflight allows broad methods: {acam}",
                "Restrict allowed methods to those strictly needed.",
                penalty=2
            )

    # ==================
    # Cookies & Sessions
    # ==================
    set_cookies = _getall_set_cookie(headers)
    summary["has_set_cookie"] = bool(set_cookies)

    # Duplicate cookie name (parity: "Set-Cookie — Repeated ID") & conflicts
    by_name: Dict[str, List[Dict[str, str]]] = {}
    for line in set_cookies:
        c = _parse_cookie_line(line)
        name = c.get("name", "").strip()
        if not name or any(ch.isspace() for ch in name):
            add_issue(
                "COOKIE_NAME_INVALID",
                "Set-Cookie — Invalid cookie name",
                _sev(3),  # LOW
                f"Cookie name appears invalid: '{name}'.",
                "Use a non-empty token without whitespace characters.",
                penalty=2
            )
        by_name.setdefault(name or "<cookie>", []).append(c)

        is_secure = "secure" in c
        is_httponly = "httponly" in c
        samesite = (c.get("samesite") or "").lower()

        if scheme == "http":
            add_issue(
                "COOKIE_OVER_HTTP",
                f"Cookie '{name or '<cookie>'}' — Sent over HTTP",
                _sev(0),  # CRITICAL
                "Cookies set over HTTP can be intercepted and hijacked.",
                "Serve pages over HTTPS and set cookie with 'Secure; HttpOnly; SameSite=Lax/Strict'.",
                penalty=25
            )
        if scheme == "https" and not is_secure:
            add_issue(
                "COOKIE_NO_SECURE",
                f"Cookie '{name or '<cookie>'}' — Missing 'Secure'",
                _sev(2),
                "Cookie may be sent over unsecured channels.",
                "Add 'Secure' attribute for cookies on HTTPS sites.",
                penalty=6
            )
        if not is_httponly:
            add_issue(
                "COOKIE_NO_HTTPONLY",
                f"Cookie '{name or '<cookie>'}' — Missing 'HttpOnly'",
                _sev(2),
                "Cookies accessible to JavaScript increase XSS impact.",
                "Add 'HttpOnly' to session/auth cookies.",
                penalty=6
            )
        if not samesite:
            add_issue(
                "COOKIE_NO_SAMESITE",
                f"Cookie '{name or '<cookie>'}' — Missing 'SameSite'",
                _sev(2),
                "Missing SameSite increases CSRF risk.",
                "Add 'SameSite=Lax' or 'SameSite=Strict'; if 'None', must include 'Secure'.",
                penalty=5
            )
        if samesite == "none" and not is_secure:
            add_issue(
                "COOKIE_NONE_NO_SECURE",
                f"Cookie '{name or '<cookie>'}' — SameSite=None without Secure",
                _sev(1),
                "Cookies with SameSite=None must be marked Secure.",
                "Add 'Secure' attribute when using 'SameSite=None'.",
                penalty=10
            )

    for name, variants in by_name.items():
        if len(variants) > 1:
            add_issue(
                "COOKIE_DUPLICATE_NAME",
                "Set-Cookie — Repeated ID",
                _sev(3),  # LOW
                f"Cookie name '{name}' is set multiple times in the same response.",
                "Set a cookie name once per response, or ensure duplicates are identical.",
                penalty=2
            )
            # Conflicting attributes?
            attrs = [{"secure": ("secure" in v), "httponly": ("httponly" in v), "samesite": (v.get("samesite") or "").lower()} for v in variants]
            if len({(a["secure"], a["httponly"], a["samesite"]) for a in attrs}) > 1:
                add_issue(
                    "COOKIE_CONFLICTING_ATTRIBUTES",
                    "Set-Cookie — Conflicting attributes",
                    _sev(2),  # MEDIUM
                    f"Cookie '{name}' is set with conflicting attributes in the same response.",
                    "Ensure the cookie is set consistently with the same attributes.",
                    penalty=5
                )

    # ========================
    # Caching / Privacy checks
    # ========================
    cache_ctrl = (headers.get("cache-control") or "").lower()
    is_sensitive_page = has_password_form or _is_login_like_url(url)

    if is_sensitive_page and is_html:
        if not (("no-store" in cache_ctrl) or ("no-cache" in cache_ctrl)):
            add_issue(
                "CACHE_SENSITIVE",
                "Cache-Control — Sensitive content cacheable",
                _sev(2),  # MEDIUM
                "Login or credential-related pages should not be cached by browser or proxies.",
                "Set 'Cache-Control: no-store' (preferred) or at least 'no-cache' on sensitive endpoints.",
                penalty=6
            )
    if is_html and summary["has_set_cookie"]:
        if "public" in cache_ctrl or not cache_ctrl:
            add_issue(
                "CACHE_COOKIE_PUBLIC",
                "Cache-Control — Cookie-setting response publicly cacheable",
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
                f"{hdr_name} — Version disclosed",
                _sev(3),  # LOW
                f"Header reveals software version: {value}",
                "Remove or generalize version-identifying headers to reduce targeted exploits.",
                penalty=2
            )
        elif value:
            add_issue(
                "TECH_STACK_DISCLOSED",
                f"{hdr_name} — Technology disclosed",
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
            "X-XSS-Protection — Deprecated header present",
            _sev(4),  # INFO
            f"Found X-XSS-Protection: {x_xss}. Modern browsers ignore it; rely on CSP instead.",
            "Remove X-XSS-Protection and implement a robust CSP.",
            penalty=0
        )
    else:
        # Parity visibility: report as INFO that it is missing (deprecated).
        add_issue(
            "XXSS_DEPRECATED_MISSING",
            "X-XSS-Protection — Missing (deprecated)",
            _sev(4),  # INFO
            "X-XSS-Protection is deprecated and generally unnecessary today.",
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

    # =========================
    # Aggregate 'ineffective' (parity-style remediation messaging)
    # =========================
    # If we marked 2+ names ineffective, create a single INFO roll-up,
    # similar to BitSight's remediation panel wording.
    if len(set(ineffective_names)) >= 2:
        names_str = ", ".join(sorted(set(ineffective_names)))
        add_issue(
            "INEFFECTIVE_HEADERS_ROLLUP",
            f"Ineffective headers: {names_str}",
            _sev(4),  # INFO
            "One or more headers are present but implemented in ways that reduce effectiveness.",
            "Ensure headers conform to best practices (single header, valid values, no contradictory directives).",
            penalty=0
        )

    # Final clamp & return
    score = max(0, min(100, score))
    return score, issues, summary
