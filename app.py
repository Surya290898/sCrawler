import asyncio
import streamlit as st
import pandas as pd
import altair as alt
from urllib.parse import urlparse

from crawler.crawl import Crawler, DEFAULT_UA
from crawler.auth import AuthConfig
from crawler.report import (
    to_dataframe, to_csv, to_json,
    issues_to_dataframe, issues_to_csv, issues_to_json,
    overall_site_score
)

# -------------------------
# Page config
# -------------------------
st.set_page_config(page_title="Authorized Crawler", page_icon="🕷️", layout="wide")
st.title("🕷️ Authorized Web Crawler")
st.caption("For in-scope, authorized discovery only. Passive header analysis — no bypassing protections.")

# -------------------------
# Session state init
# -------------------------
for key, default in [
    ("results_pages_df", None),
    ("results_issues_df", None),
    ("site_score", None),
    ("last_params", {}),
    ("message", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# -------------------------
# Helpers
# -------------------------
def _read_targets_from_file(uploaded_file) -> list[str]:
    """
    Read URLs from uploaded .xlsx or .csv.
    Heuristics:
      - looks for columns: url/urls/target/targets (case-insensitive), else first column
      - keeps only http/https with netloc
      - de-duplicates while preserving order
    Returns a list of validated URLs.
    """
    urls: list[str] = []
    try:
        name = (uploaded_file.name or "").lower()
        if name.endswith(".xlsx") or name.endswith(".xls"):
            df = pd.read_excel(uploaded_file, engine="openpyxl")
        elif name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        else:
            st.warning("Unsupported file type. Upload a .xlsx or .csv file.")
            return []

        if df.empty:
            return []

        # Select column
        cand = [c for c in df.columns if str(c).strip().lower() in ("url", "urls", "target", "targets")]
        col = cand[0] if cand else df.columns[0]
        series = df[col].dropna()

        for val in series.tolist():
            u = str(val).strip()
            if not u:
                continue
            p = urlparse(u)
            if p.scheme in ("http", "https") and p.netloc:
                urls.append(u)

    except Exception as e:
        st.error(f"Could not read uploaded file: {e}")
        return []

    # De-duplicate while preserving order
    return list(dict.fromkeys(urls))

def _build_severity_chart(df_issues: pd.DataFrame):
    """
    Altair bar chart with fixed severity colors:
      CRITICAL - #7f1d1d (dark red)
      HIGH     - #dc2626 (red)
      MEDIUM   - #f97316 (orange)
      LOW      - #eab308 (yellow)
      INFO     - #3b82f6 (blue)
    Uses list-of-dicts data to avoid Narwhals duplicate-column checks.
    """
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    palette = {
        "CRITICAL": "#7f1d1d",
        "HIGH": "#dc2626",
        "MEDIUM": "#f97316",
        "LOW": "#eab308",
        "INFO": "#3b82f6",
    }

    # Start with zeros for all severities
    counts_map = {sev: 0 for sev in order}

    if df_issues is not None and not df_issues.empty and "severity" in df_issues.columns:
        vc = df_issues["severity"].value_counts()
        for sev, cnt in vc.items():
            if sev in counts_map:
                counts_map[sev] = int(cnt)

    data = [{"severity": sev, "count": counts_map[sev]} for sev in order]

    chart = (
        alt.Chart(alt.Data(values=data))
        .mark_bar()
        .encode(
            x=alt.X("severity:N", sort=order, title="Severity"),
            y=alt.Y("count:Q", title="Findings"),
            color=alt.Color(
                "severity:N",
                sort=order,
                scale=alt.Scale(domain=order, range=[palette[s] for s in order]),
                legend=None,
            ),
            tooltip=[alt.Tooltip("severity:N"), alt.Tooltip("count:Q")]
        )
        .properties(height=260)
    )
    return chart

# -------------------------
# Sidebar controls
# -------------------------
with st.sidebar:
    st.header("Scan Targets")

    # Single URL (kept as-is)
    start_url = st.text_input("Single URL (optional)", placeholder="https://example.com")

    # Bulk URLs via file
    target_file = st.file_uploader(
        "Bulk URLs file (optional) — .xlsx or .csv",
        type=["xlsx", "xls", "csv"],
        accept_multiple_files=False,
        help="File should contain a column named 'url' (or the first column will be used)."
    )

    st.header("Scope & Limits")
    allow_subdomains = st.checkbox("Allow subdomains", True)
    max_depth = st.number_input("Max depth", min_value=0, max_value=10, value=3)
    max_pages = st.number_input("Max pages (per target)", min_value=1, max_value=5000, value=500)
    concurrency = st.slider("Concurrency", min_value=1, max_value=32, value=8)
    respect_robots = st.checkbox("Respect robots.txt", value=True)
    rate_min = st.number_input("Rate delay min (sec)", min_value=0.0, max_value=3.0, value=0.1, step=0.1)
    rate_max = st.number_input("Rate delay max (sec)", min_value=0.0, max_value=5.0, value=0.5, step=0.1)
    ua = st.text_input("User-Agent", value=DEFAULT_UA)

    st.header("Authentication (Optional — authorized targets)")
    auth_mode = st.selectbox("Auth Type", ["None", "Basic", "Cookie", "Login Form"])

    basic_user = basic_pass = None
    cookie_string = None
    login_url = username_field = password_field = username_value = password_value = None
    extra = {}

    if auth_mode == "Basic":
        basic_user = st.text_input("Basic username")
        basic_pass = st.text_input("Basic password", type="password")
    elif auth_mode == "Cookie":
        cookie_string = st.text_area("Cookie header value", help="e.g., SESSIONID=...; csrftoken=...", height=80)
    elif auth_mode == "Login Form":
        login_url = st.text_input("Login URL")
        username_field = st.text_input("Username field name", value="username")
        password_field = st.text_input("Password field name", value="password")
        username_value = st.text_input("Username")
        password_value = st.text_input("Password", type="password")
        extra_kv = st.text_area("Extra form fields (key=value per line)", placeholder="csrf_token=abcd1234")
        if extra_kv:
            for line in extra_kv.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    extra[k.strip()] = v.strip()

    st.markdown("---")
    exclude_prefixes = st.text_area(
        "Exclude URL prefixes (one per line)",
        placeholder="https://example.com/logout\nhttps://example.com/admin",
        height=90
    ).splitlines()

    cols_sidebar = st.columns([1, 1])
    with cols_sidebar[0]:
        run_button = st.button("Start Crawl", type="primary")
    with cols_sidebar[1]:
        reset_button = st.button("New scan / Reset", help="Clear results and start a new scan")

# -------------------------
# Reset flow
# -------------------------
if reset_button:
    st.session_state.results_pages_df = None
    st.session_state.results_issues_df = None
    st.session_state.site_score = None
    st.session_state.last_params = {}
    st.session_state.message = "State cleared. Configure parameters and click Start Crawl."
    st.experimental_rerun()

# -------------------------
# Run crawl (single or bulk)
# -------------------------
if run_button:
    # Gather targets
    targets: list[str] = []
    if isinstance(start_url, str) and start_url.strip():
        su = start_url.strip()
        p = urlparse(su)
        if p.scheme in ("http", "https") and p.netloc:
            targets.append(su)
        else:
            st.warning("Single URL ignored because it is not a valid http/https URL.")

    if target_file is not None:
        file_urls = _read_targets_from_file(target_file)
        targets.extend(file_urls)

    # De-duplicate final list
    targets = list(dict.fromkeys([t.strip() for t in targets if t.strip()]))

    if not targets:
        st.error("Provide at least one target: Single URL and/or a bulk file (.xlsx/.csv).")
        st.stop()

    st.info(f"Starting crawl for {len(targets)} target(s). This may take a while depending on limits and site sizes.")
    progress = st.progress(0)

    # Auth config (same for all targets)
    auth = AuthConfig(
        basic_user=basic_user,
        basic_pass=basic_pass,
        cookie_string=cookie_string,
        login_url=login_url,
        username_field=username_field,
        password_field=password_field,
        username_value=username_value,
        password_value=password_value,
        extra_fields=extra,
    )

    all_pages: list[pd.DataFrame] = []
    all_issues: list[pd.DataFrame] = []

    for idx, target in enumerate(targets, start=1):
        # Build crawler per target
        crawler = Crawler(
            start_url=target,
            allow_subdomains=allow_subdomains,
            max_depth=int(max_depth),
            max_pages=int(max_pages),
            concurrency=int(concurrency),
            respect_robots=bool(respect_robots),
            rate_delay_range=(float(rate_min), float(rate_max)) if rate_max >= rate_min else (float(rate_max), float(rate_min)),
            user_agent=ua.strip() or DEFAULT_UA,
            exclude_prefixes=[p.strip() for p in exclude_prefixes if p.strip()],
            auth=auth,
        )

        async def run_and_collect():
            await crawler.run()
            return crawler.findings, crawler.issues

        findings, issues = asyncio.run(run_and_collect())

        # Convert to DataFrames
        df_pages = to_dataframe(findings) if findings else pd.DataFrame()
        df_issues = issues_to_dataframe(issues) if issues else pd.DataFrame()

        # Tag with seed to keep provenance when merged
        if not df_pages.empty:
            df_pages.insert(0, "seed", target)
            all_pages.append(df_pages)
        if not df_issues.empty:
            df_issues.insert(0, "seed", target)
            all_issues.append(df_issues)

        progress.progress(int(idx * 100 / len(targets)))

    # Merge across targets
    df_pages_all = pd.concat(all_pages, ignore_index=True) if all_pages else pd.DataFrame()
    df_issues_all = pd.concat(all_issues, ignore_index=True) if all_issues else pd.DataFrame()

    if df_pages_all.empty and df_issues_all.empty:
        st.warning("No pages crawled or no issues found across the provided targets. Check scope/limits/auth and try again.")
        st.stop()

    # Aggregate overall score (simple mean proxy)
    try:
        site_score = int(df_pages_all["security_score"].mean()) if "security_score" in df_pages_all.columns and not df_pages_all.empty else 0
    except Exception:
        site_score = 0

    # Persist in session_state
    st.session_state.results_pages_df = df_pages_all
    st.session_state.results_issues_df = df_issues_all
    st.session_state.site_score = site_score
    st.session_state.last_params = {
        "targets": targets,
        "allow_subdomains": allow_subdomains,
        "max_depth": int(max_depth),
        "max_pages": int(max_pages),
        "concurrency": int(concurrency),
        "respect_robots": bool(respect_robots),
        "rate_range": (float(rate_min), float(rate_max)) if rate_max >= rate_min else (float(rate_max), float(rate_min)),
        "ua": ua.strip() or DEFAULT_UA,
        "exclude_prefixes": [p.strip() for p in exclude_prefixes if p.strip()],
        "auth_mode": auth_mode,
    }

# -------------------------
# Results view (persistent)
# -------------------------
if st.session_state.results_pages_df is not None:
    df_pages = st.session_state.results_pages_df
    df_issues = st.session_state.results_issues_df
    site_score = int(st.session_state.site_score or 0)

    total_pages = len(df_pages) if df_pages is not None else 0
    st.success(
        f"Crawl finished. Total pages visited: {total_pages}  |  Overall Security Score (avg): {site_score}/100"
    )

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Avg Page Score", int(df_pages["security_score"].mean()) if ("security_score" in df_pages.columns and not df_pages.empty) else 0)
    with c2:
        st.metric("Pages missing CSP", int((~df_pages["hdr_csp"]).sum()) if ("hdr_csp" in df_pages.columns) else 0)
    with c3:
        st.metric("Password forms over HTTP", int(df_pages["password_form_over_http"].sum()) if ("password_form_over_http" in df_pages.columns) else 0)
    with c4:
        st.metric("HTTP errors (>=400)", int((df_pages['status'] >= 400).sum()) if ("status" in df_pages.columns) else 0)

    # Severity Breakdown (Altair with custom colors; list-of-dicts to avoid Narwhals DuplicateError)
    st.subheader("Severity Breakdown")
    if df_issues is not None and not df_issues.empty and "severity" in df_issues.columns:
        chart = _build_severity_chart(df_issues)
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("No issues detected by header audit.")

    # Pages Table
    with st.expander("📄 Pages (with security score)", expanded=True):
        # Include 'seed' column if present
        base_cols = [
            "seed" if "seed" in df_pages.columns else None,
            "final_url","status","title","content_type",
            "security_score",
            "hdr_csp","hdr_xfo","hdr_hsts","hdr_xcto","hdr_refpol",
            "has_password_form","password_form_over_http",
            "num_outlinks_internal","num_outlinks_external"
        ]
        cols = [c for c in base_cols if c is not None and c in df_pages.columns]
        if cols:
            view = df_pages[cols].sort_values(by=["seed","security_score"] if "seed" in cols else "security_score")
            st.dataframe(view, use_container_width=True, hide_index=True)
        else:
            st.info("No page columns available to display.")

    # Issues Table
    with st.expander("🛡️ Issues (OWASP-aligned)", expanded=True):
        if df_issues is not None and not df_issues.empty:
            default_sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sev_filter = st.multiselect(
                "Filter by severity",
                options=default_sev,
                default=default_sev
            )
            view_issues = df_issues[df_issues["severity"].isin(sev_filter)].copy() if "severity" in df_issues.columns else df_issues.copy()
            show_cols = ["seed"] if "seed" in view_issues.columns else []
            show_cols += ["severity","title","url","check_id","description","recommendation"]
            show_cols = [c for c in show_cols if c in view_issues.columns]
            st.dataframe(
                view_issues[show_cols],
                use_container_width=True, hide_index=True
            )
        else:
            st.info("No issues flagged.")

    # Downloads (use cached DFs so page stays as-is after click)
    st.subheader("Downloads")
    cdl1, cdl2, cdl3, cdl4 = st.columns(4)
    with cdl1:
        st.download_button(
            "⬇️ Pages CSV",
            data=df_pages.to_csv(index=False).encode("utf-8"),
            file_name="pages.csv",
            mime="text/csv",
            key="dl_pages_csv"
        )
    with cdl2:
        st.download_button(
            "⬇️ Pages JSON",
            data=df_pages.to_json(orient="records", indent=2).encode("utf-8"),
            file_name="pages.json",
            mime="application/json",
            key="dl_pages_json"
        )
    with cdl3:
        if df_issues is not None:
            st.download_button(
                "⬇️ Issues CSV",
                data=df_issues.to_csv(index=False).encode("utf-8"),
                file_name="issues.csv",
                mime="text/csv",
                key="dl_issues_csv"
            )
    with cdl4:
        if df_issues is not None:
            st.download_button(
                "⬇️ Issues JSON",
                data=df_issues.to_json(orient="records", indent=2).encode("utf-8"),
                file_name="issues.json",
                mime="application/json",
                key="dl_issues_json"
            )

    if st.session_state.message:
        st.info(st.session_state.message)
        st.session_state.message = None

else:
    # Home view (only shows when no results are cached)
    if st.session_state.message:
        st.info(st.session_state.message)
        st.session_state.message = None
    else:
        st.info("Add a Single URL and/or upload a Bulk URLs file, configure scope/auth, then click **Start Crawl**.")
