from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import pandas as pd
from urllib.parse import urlparse

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
    """Simple mean of page scores (0..100)."""
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

# Heuristic “fix location” hints per check family (canonical header keys)
_FIX_HINTS = {
    "Content-Security-Policy": "Web server / application global response headers (CSP policy)",
    "Strict-Transport-Security": "Web server / reverse proxy (HTTPS only) — Strict-Transport-Security",
    "X-Frame-Options": "Web server / application global headers",
    "X-Content-Type-Options": "Web server / application global headers",
    "Referrer-Policy": "Web server / application global headers",
    "Permissions-Policy": "Web server / application global headers",
    "Feature-Policy": "Web server / application global headers (deprecated — migrate to Permissions-Policy)",
    "Cross-Origin-Resource-Policy": "Web server / application global headers (CORP)",
    "Cross-Origin-Embedder-Policy": "Web server / application global headers (COEP)",
    "Cross-Origin-Opener-Policy": "Web server / application global headers (COOP)",
    "Expect-CT": "Web server / TLS config (deprecated header)",
    "Access-Control-Allow-Origin": "API gateway / origin server CORS configuration",
    "Access-Control-Allow-Methods": "API gateway / origin server CORS configuration",
    "Set-Cookie": "Application/session middleware where cookies are set",
    "Cache-Control": "Application cache policy / reverse proxy",
    "Server": "Web server banner / reverse proxy config",
    "X-Powered-By": "Application platform/framework configuration",
    "X-AspNet-Version": "Framework configuration",
    "Directory listing": "Web server directory indexes"
}

def _canonical_family_from_title_or_id(title: str, check_id: str) -> str:
    """
    Normalize a finding into a canonical 'family' (header/policy name)
    used to propose a fix-once location.
    """
    t = (title or "").lower()
    cid = (check_id or "").upper()

    pairs = [
        ("content-security-policy", "Content-Security-Policy"),
        ("strict-transport-security", "Strict-Transport-Security"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
        ("feature-policy", "Feature-Policy"),
        ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
        ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
        ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
        ("expect-ct", "Expect-CT"),
        ("access-control-allow-origin", "Access-Control-Allow-Origin"),
        ("access-control-allow-methods", "Access-Control-Allow-Methods"),
        ("set-cookie", "Set-Cookie"),
        ("cache-control", "Cache-Control"),
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "X-AspNet-Version"),
        ("server", "Server"),
        ("directory listing", "Directory listing"),
    ]
    for needle, canon in pairs:
        if needle in t:
            return canon

    # Fallback by check_id
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

    return "Server"

def _host_from_url(u: str) -> str:
    try:
        return urlparse(u).netloc or ""
    except Exception:
        return ""

def _longest_common_path_prefix(urls: List[str]) -> str:
    paths = []
    for u in urls:
        try:
            p = urlparse(u)
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
    issues_df: Optional[pd.DataFrame],
    pages_df: Optional[pd.DataFrame] = None
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

    # Enrich with host and seed
    if "url" in df.columns:
        df["host"] = df["url"].apply(_host_from_url)
    else:
        df["host"] = ""

    if "seed" not in df.columns:
        df["seed"] = ""

    # Grouping key
    group_cols = ["seed", "host", "check_id", "title", "severity"]

    # Totals per (seed, host) to compute coverage
    totals_map: Dict[tuple, int] = {}
    if pages_df is not None and not pages_df.empty:
        pp = pages_df.copy()
        if "final_url" in pp.columns:
            pp["host"] = pp["final_url"].apply(_host_from_url)
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

        # Scope inference
        scope = "page-level"
        if coverage is not None and coverage >= 0.8 and affected_pages >= 5:
            scope = "site-wide (likely global header/policy)"
        elif affected_pages >= 3:
            prefix = _longest_common_path_prefix(list(g["url"].dropna().unique()))
            scope = f"path-segment ({prefix})" if prefix not in ("/", "") else "multiple pages"

        family = _canonical_family_from_title_or_id(title, check_id)
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

    # Stable sort: severity then affected_pages desc
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if not agg.empty:
        agg["__sev_rank"] = agg["severity"].map(lambda s: sev_rank.get(s, 9))
        agg = agg.sort_values(by=["__sev_rank", "affected_pages"], ascending=[True, False]).drop(columns="__sev_rank")

    return agg

def unique_findings_to_csv(df_unique: pd.DataFrame) -> bytes:
    return df_unique.to_csv(index=False).encode("utf-8")

def unique_findings_to_json(df_unique: pd.DataFrame) -> bytes:
    return df_unique.to_json(orient="records", indent=2).encode("utf-8")
