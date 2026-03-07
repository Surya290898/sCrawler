# app.py
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
    overall_site_score,
)
# Try unique-findings helpers if present in your repo
try:
    from crawler.report import aggregate_unique_findings, unique_findings_to_csv, unique_findings_to_json
    HAVE_UNIQUE = True
except Exception:
    HAVE_UNIQUE = False

# === NEW: Browserless cloud crawler (no Docker/VM needed)
try:
    from crawler.jscloud_crawl import JSCloudCrawler
    HAVE_JSCLOUD = True
except Exception:
    JSCloudCrawler = None
    HAVE_JSCLOUD = False


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
    ("results_unique_df", None),
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
            # Requires openpyxl in requirements
            df = pd.read_excel(uploaded_file, engine="openpyxl")
        elif name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        else:
            st.warning("Unsupported file type. Upload a .xlsx or .csv file.")
            return []

        if df.empty:
            return []

        # Select column by heuristic
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

def _read_targets_from_text(text_block: str) -> list[str]:
    """NEW: plain-text bulk URL seeder (one URL per line)."""
    urls: list[str] = []
    for line in (text_block or "").splitlines():
        u = line.strip()
        if not u:
            continue
        p = urlparse(u)
        if p.scheme in ("http", "https") and p.netloc:
            urls.append(u)
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

    # Single URL (optional)
    start_url = st.text_input("Single URL (optional)", placeholder="https://example.com")

    # Bulk URLs via file
    target_file = st.file_uploader(
        "Bulk URLs file (optional) — .xlsx or .csv",
        type=["xlsx", "xls", "csv"],
        accept_multiple_files=False,
        help="File should contain a column named 'url' (or the first column will be used)."
    )

    # === NEW: Bulk URL Seeder (paste list)
    bulk_text = st.text_area(
        "Additional URLs (optional) — paste one per line",
        placeholder="https://site.example/route-a\nhttps://site.example/route-b"
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

    st.header("JavaScript (Browserless Cloud) — No Docker/VM")
    if HAVE_JSCLOUD:
        enable_js_cloud = st.checkbox(
            "Enable JS Cloud via Browserless",
            value=False,
            help="Runs a real browser on Browserless via REST. If empty token/endpoint, falls back to HTTP crawler."
        )
    else:
        enable_js_cloud = st.checkbox(
            "Enable JS Cloud via Browserless",
            value=False, disabled=True,
            help="Module missing. Add crawler/jscloud_crawl.py to enable this."
        )

    # Browserless settings
    bl_endpoint = st.text_input(
        "Browserless endpoint",
        value="https://production-sfo.browserless.io",
        help="Default cloud endpoint."
    )
    bl_token = st.text_input(
        "Browserless API token",
        type="password",
        help="Get from Browserless dashboard."
    )
    click_sel_txt = st.text_input(
        "Click selectors (comma separated)",
        value="a[role='button'],button,[role='button']",
        help="Used to discover SPA routes. Keep small; clicks are limited."
    )
    clicks_per_page = st.slider("Clicks per page (0-3)", min_value=0, max_value=3, value=0)
    goto_wait_until = st.selectbox("waitUntil", ["load", "domcontentloaded", "networkidle"], index=2)

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
    st.session_state.results_unique_df = None
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

    # === NEW: Bulk URL seeder from text
    text_urls = _read_targets_from_text(bulk_text)
    targets.extend(text_urls)

    # De-duplicate final list
    targets = list(dict.fromkeys([t.strip() for t in targets if t.strip()]))

    if not targets:
        st.error("Provide at least one target: Single URL, bulk file, and/or the pasted URL list.")
        st.stop()

    st.info(f"Starting crawl for {len(targets)} target(s). This may take a while depending on limits and site sizes.")
    progress = st.progress(0)

    auth_cfg = AuthConfig(
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

    # Shared extra headers for cloud browser calls (UA, Cookie if provided)
    cloud_headers = {}
    if cookie_string:
        cloud_headers["Cookie"] = cookie_string
    if ua and ua.strip():
        cloud_headers["User-Agent"] = ua.strip()

    # Click selectors list
    click_selectors = [s.strip() for s in (click_sel_txt or "").split(",") if s.strip()]

    for idx, target in enumerate(targets, start=1):
        # Decide mode for this target
        use_js_cloud = bool(
            enable_js_cloud and HAVE_JSCLOUD and bl_token.strip() and bl_endpoint.strip()
        )

        if use_js_cloud:
            crawler = JSCloudCrawler(
                start_url=target,
                endpoint=bl_endpoint.strip(),
                api_token=bl_token.strip(),
                allow_subdomains=allow_subdomains,
                max_depth=int(max_depth),
                max_pages=int(max_pages),
                concurrency=max(1, int(min(concurrency, 6))),  # cloud browser is heavier; keep reasonable
                rate_delay_range=(float(rate_min), float(rate_max)) if rate_max >= rate_min else (float(rate_max), float(rate_min)),
                user_agent=ua.strip() or DEFAULT_UA,
                exclude_prefixes=[p.strip() for p in exclude_prefixes if p.strip()],
                click_selectors=click_selectors,
                max_clicks_per_page=int(clicks_per_page),
                goto_wait_until=goto_wait_until,
                extra_headers=cloud_headers,
                http_auth=(basic_user, basic_pass) if (basic_user and basic_pass) else None,
            )

            async def run_and_collect():
                await crawler.run()
                return crawler.findings, crawler.issues

        else:
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
                auth=auth_cfg,
            )

            async def run_and_collect():
                await crawler.run()
                return crawler.findings, crawler.issues

        # Run
        try:
            findings, issues = asyncio.run(run_and_collect())
        except Exception as e:
            # In case cloud call fails unexpectedly, fall back to HTTP mode
            if use_js_cloud:
                st.warning(f"JS Cloud failed for {target}. Falling back to HTTP crawler.")
                http_crawler = Crawler(
                    start_url=target,
                    allow_subdomains=allow_subdomains,
                    max_depth=int(max_depth),
                    max_pages=int(max_pages),
                    concurrency=int(concurrency),
                    respect_robots=bool(respect_robots),
                    rate_delay_range=(float(rate_min), float(rate_max)) if rate_max >= rate_min else (float(rate_max), float(rate_min)),
                    user_agent=ua.strip() or DEFAULT_UA,
                    exclude_prefixes=[p.strip() for p in exclude_prefixes if p.strip()],
                    auth=auth_cfg,
                )
                async def _http_run():
                    await http_crawler.run()
                    return http_crawler.findings, http_crawler.issues
                findings, issues = asyncio.run(_http_run())
            else:
                raise

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
        st.warning("No pages crawled or no issues found across the provided targets.")
        with st.expander("Debug tips", expanded=True):
            st.markdown("""
- **Robots blocked (HTTP mode)**: Uncheck **Respect robots.txt** in the sidebar and retry.
- **Scope blocked**: Ensure **Allow subdomains** is correct. Start from the canonical (post-redirect) host.
- **Depth/limits**: Increase **Max depth** (e.g., 3→5) and **Max pages** (e.g., 500→2000).
- **Auth/redirects**: If the start URL redirects to login or a different host, use **Login Form**/**Cookie** auth, or start from a public in-scope page.
- **SPA/JS navigation**: Turn ON **JS Cloud (Browserless)** and supply **Endpoint + API token**.
""")
        st.stop()

    # Aggregate overall score (simple mean proxy for display)
    try:
        site_score = int(df_pages_all["security_score"].mean()) if "security_score" in df_pages_all.columns and not df_pages_all.empty else 0
    except Exception:
        site_score = 0

    # Unique (de-duplicated) findings with safety guard
    df_unique = pd.DataFrame()
    if HAVE_UNIQUE:
        try:
            df_unique = aggregate_unique_findings(df_issues_all, df_pages_all)
        except Exception:
            st.warning("Unique-findings aggregation failed on this run. Raw results are still available.")
            df_unique = pd.DataFrame()

    # Persist in session_state
    st.session_state.results_pages_df = df_pages_all
    st.session_state.results_issues_df = df_issues_all
    st.session_state.results_unique_df = df_unique if HAVE_UNIQUE else None
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
        "enable_js_cloud": bool(enable_js_cloud),
    }

# -------------------------
# Results view (persistent)
# -------------------------
if st.session_state.results_pages_df is not None:
    df_pages = st.session_state.results_pages_df
    df_issues = st.session_state.results_issues_df
    df_unique = st.session_state.results_unique_df
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

    # Severity Breakdown (colored)
    st.subheader("Severity Breakdown")
    if df_issues is not None and not df_issues.empty and "severity" in df_issues.columns:
        chart = _build_severity_chart(df_issues)
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("No issues detected by header audit.")

    # Unique findings (fix-once view) if available
    if HAVE_UNIQUE:
        with st.expander("🧩 Unique findings (de-duplicated, fix-once guidance)", expanded=True):
            if df_unique is not None and not df_unique.empty:
                show_cols = ["seed", "host", "severity", "title", "check_id", "affected_pages", "coverage", "scope", "fix_hint_location", "sample_urls"]
                show_cols = [c for c in show_cols if c in df_unique.columns]
                view = df_unique.copy()
                if "coverage" in view.columns:
                    view["coverage"] = view["coverage"].apply(lambda x: f"{x:.0%}" if pd.notnull(x) else "")
                st.dataframe(view[show_cols], use_container_width=True, hide_index=True)

                cdl_u1, cdl_u2 = st.columns(2)
                with cdl_u1:
                    st.download_button(
                        "⬇️ Unique findings CSV",
                        data=unique_findings_to_csv(df_unique),
                        file_name="unique_findings.csv",
                        mime="text/csv",
                        key="dl_unique_csv"
                    )
                with cdl_u2:
                    st.download_button(
                        "⬇️ Unique findings JSON",
                        data=unique_findings_to_json(df_unique),
                        file_name="unique_findings.json",
                        mime="application/json",
                        key="dl_unique_json"
                    )
            else:
                st.info("No unique findings aggregated (no issues found).")

    # Pages Table (raw)
    with st.expander("📄 Pages (with security score)", expanded=False):
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

    # Issues Table (raw, per page)
    with st.expander("🛡️ Issues (full evidence, per page)", expanded=False):
        if df_issues is not None and not df_issues.empty:
            default_sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sev_filter = st.multiselect(
                "Filter by severity",
                options=default_sev,
                default=default_sev,
                key="sev_filter_full"
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

    # Downloads (raw evidence)
    st.subheader("Downloads (raw evidence)")
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
        st.info("Add a Single URL and/or upload a Bulk URLs file (or paste URLs), configure scope/auth, then click **Start Crawl**.")
