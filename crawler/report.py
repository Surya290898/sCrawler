from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import pandas as pd
from urllib.parse import urlparse
import json

# -----------------------------
# Core page finding dataclass
# -----------------------------
@dataclass
class PageFinding:
    url: str
    final_url: str
    status: int
    reason: str
    title: str
    content_type: str
    content_length: int
    scheme: str
    num_outlinks_internal: int
    num_outlinks_external: int
    forms_count: int
    has_password_form: bool
    password_form_over_http: bool
    hdr_csp: bool
    hdr_xfo: bool
    hdr_hsts: bool
    hdr_xcto: bool
    hdr_refpol: bool
    # extended
    security_score: int

# -----------------------------
# Issue dataclass
# -----------------------------
@dataclass
class Issue:
    url: str
    check_id: str
    title: str
    severity: str
    description: str
    recommendation: str

# -----------------------------
# Basic converters
# -----------------------------
def to_dataframe(findings: List[PageFinding]) -> pd.DataFrame:
    return pd.DataFrame([asdict(f) for f in findings])

def to_csv(findings: List[PageFinding]) -> bytes:
    df = to_dataframe(findings)
    return df.to_csv(index=False).encode("utf-8")

def to_json(findings: List[PageFinding]) -> bytes:
    df = to_dataframe(findings)
    return df.to_json(orient="records", indent=2).encode("utf-8")

def issues_to_dataframe(issues: List[Issue]) -> pd.DataFrame:
    return pd.DataFrame([asdict(i) for i in issues])

def issues_to_csv(issues: List[Issue]) -> bytes:
    df = issues_to_dataframe(issues)
    return df.to_csv(index=False).encode("utf-8")

def issues_to_json(issues: List[Issue]) -> bytes:
    df = issues_to_dataframe(issues)
    return df.to_json(orient="records", indent=2).encode("utf-8")

def overall_site_score(findings: List[PageFinding]) -> int:
    """Weighted average leaning toward worst pages (legacy helper)."""
    if not findings:
        return 0
    scores = [max(0, min(100, f.security_score)) for f in findings]
    try:
        return int(sum(scores) / len(scores))
    except ZeroDivisionError:
        return 0

# -----------------------------
# Unique Findings Aggregation
# -----------------------------

# Heuristic “fix location” hints per check family
_FIX_HINTS = {
    # CSP/HSTS and core headers → usually global server/app headers
    "CSP": "Web server / application global response headers (CSP policy)",
    "HSTS": "Web server / reverse proxy (HTTPS only) — Strict-Transport-Security",
    "X-Frame-Options": "Web server / application global headers",
    "X-Content-Type-Options": "Web server / application global headers",
    "Referrer-Policy": "Web server / application global headers",
    "Permissions-Policy": "Web server / application global headers",
    "Feature-Policy": "Web server / application global headers (deprecated — migrate to Permissions-Policy)",
    "Cross-Origin-Resource-Policy": "Web server / application global headers (CORP)",
    "Cross-Origin-Embedder-Policy": "Web server / application global headers (COEP)",
    "Cross-Origin-Opener-Policy": "Web server / application global headers (COOP)",
    "Expect-CT": "Web server / TLS config (deprecated header)",
    # CORS
    "Access-Control-Allow-Origin": "API gateway / origin server CORS configuration",
    "Access-Control-Allow-Methods": "API gateway / origin server CORS configuration",
    # Cookies
    "Set-Cookie": "Application/session middleware where cookies are set",
    # Cache
    "Cache-Control": "Application cache policy / reverse proxy",
    # Info disclosure
    "Server": "Web server banner / reverse proxy config",
    "X-Powered-By": "Application platform/framework configuration",
    "X-AspNet-Version": "Framework configuration",
    # Other indicators
    "Directory listing": "Web server directory indexes"
}

def _header_family_from_issue_title(title: str, check_id: str) -> str:
    """
    Try to infer the header/policy family to present a fix-once location.
    Uses issue title first (parity-style titles), then falls back to check_id.
    """
    t = (title or "").lower()
    cid = (check_id or "").upper()

    # Direct name matches from title
    for key in [
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options", "referrer-policy",
        "permissions-policy", "feature-policy",
        "cross-origin-resource-policy", "cross-origin-embedder-policy", "cross-origin-opener-policy",
        "expect-ct", "access-control-allow-origin", "access-control-allow-methods",
        "set-cookie", "cache-control", "server", "x-powered-by", "x-aspnet-version",
        "directory listing"
    ]:
        if key in t:
            return key.title().replace("-", " ")

    # Derive from check_id prefixes
    if cid.startswith("CSP"):
        return "Content-Security-Policy"
    if cid.startswith("HSTS"):
        return "Strict-Transport-Security"
    if cid.startswith("CORS") or "ACAO" in cid:
        return "Access-Control-Allow-Origin"
    if cid.startswith("COOKIE"):
        return "Set-Cookie"
    if cid.startswith("CACHE"):
        return "Cache-Control"
    if cid.startswith("TECH_"):
        return "Server"
    if cid.startswith("DIR_LISTING"):
        return "Directory listing"

    # Default fallback
    return "Web server / application"

def _longest_common_path_prefix(urls: List[str]) -> str:
    """
    Compute a path-prefix hint across urls: /a/b/ ; returns '/' if no commonality.
    """
    paths = []
    for u in urls:
        try:
            p = urlparse(u)
            # normalize
            segs = [s for s in (p.path or "/").split("/") if s]
            paths.append(segs)
        except Exception:
            pass
    if not paths:
        return "/"
    min_len = min(len(p) for p in paths)
    prefix = []
    for i in range(min_len):
        token = paths[0][i]
        if all(i < len(p) and p[i] == token for p in paths):
            prefix.append(token)
        else:
            break
    return "/" + "/".join(prefix) + ("/" if prefix else "")

def aggregate_unique_findings(
    issues_df: Optional(pd.DataFrame),
    pages_df: Optional(pd.DataFrame) = None
) -> pd.DataFrame:
    """
    Collapse per-page issues into unique, fix-once items per (seed, host, check_id, title, severity).

    Adds:
      - host
      - affected_pages
      - coverage (affected_pages / total_pages_on_host_for_seed) if pages_df provided
      - scope (site-wide | path-segment | page-level)
      - fix_hint_location (where to apply)
      - sample_urls (up to 3)
    """
    if issues_df is None or issues_df.empty:
        return pd.DataFrame()

    df = issues_df.copy()

    # derive host and seed (if present)
    def _host_from_url(u: str) -> str:
        try:
            return urlparse(u).netloc or ""
        except Exception:
            return ""

    if "url" in df.columns:
        df["host"] = df["url"].apply(_host_from_url)
    else:
        df["host"] = ""

    if "seed" not in df.columns:
        df["seed"] = ""

    # group key
    group_cols = ["seed", "host", "check_id", "title", "severity"]

    # helper: per-host page totals to compute coverage
    totals_map: Dict[tuple, int] = {}
    if pages_df is not None and not pages_df.empty:
        pp = pages_df.copy()
        # where do we get host? from final_url
        if "final_url" in pp.columns:
            pp["host"] = pp["final_url"].apply(lambda u: urlparse(u).netloc if isinstance(u, str) else "")
        else:
            pp["host"] = ""
        if "seed" not in pp.columns:
            pp["seed"] = ""
        totals = pp.groupby(["seed", "host"], dropna=False)["final_url"].nunique().reset_index(name="total_pages")
        for _, row in totals.iterrows():
            totals_map[(row.get("seed", ""), row.get("host", ""))] = int(row.get("total_pages", 0))

    rows = []
    for key, g in df.groupby(group_cols, dropna=False):
        seed, host, check_id, title, severity = key
        affected_pages = int(g["url"].nunique()) if "url" in g.columns else len(g)
        sample_urls = list(g["url"].dropna().unique()[:3]) if "url" in g.columns else []
        total_pages = totals_map.get((seed, host), 0)
        coverage = (affected_pages / total_pages) if total_pages > 0 else None

        # scope inference
        scope = "page-level"
        if coverage is not None and coverage >= 0.8 and affected_pages >= 5:
            scope = "site-wide (likely global header/policy)"
        elif affected_pages >= 3:
            # derive path prefix
            prefix = _longest_common_path_prefix(list(g["url"].dropna().unique()))
            if prefix not in ("/", ""):
                scope = f"path-segment ({prefix})"
            else:
                scope = "multiple pages"

        family = _header_family_from_issue_title(title, check_id)
        fix_hint_location = _FIX_HINTS.get(family, "Web server / application global configuration")

        rows.append({
            "seed": seed,
            "host": host,
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "affected_pages": affected_pages,
            "coverage": coverage,
            "scope": scope,
            "fix_hint_location": fix_hint_location,
            "sample_urls": "; ".join(sample_urls)
        })

    agg = pd.DataFrame(rows)

    # Stable sort: by severity rank then affected_pages desc
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if not agg.empty:
        agg["__sev_rank"] = agg["severity"].map(lambda s: sev_rank.get(s, 9))
        agg = agg.sort_values(by=["__sev_rank", "affected_pages"], ascending=[True, False]).drop(columns="__sev_rank")

    return agg

def unique_findings_to_csv(df_unique: pd.DataFrame) -> bytes:
    return df_unique.to_csv(index=False).encode("utf-8")

def unique_findings_to_json(df_unique: pd.DataFrame) -> bytes:
    return df_unique.to_json(orient="records", indent=2).encode("utf-8")
