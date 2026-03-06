import asyncio
import streamlit as st
import pandas as pd

from crawler.crawl import Crawler, DEFAULT_UA
from crawler.auth import AuthConfig
from crawler.report import to_dataframe, to_csv, to_json

st.set_page_config(page_title="Authorized Crawler", page_icon="🕷️", layout="wide")

st.title("🕷️ Authorized Web Crawler")
st.caption("For in-scope, authorized discovery only. No bypassing authentication or protections.")

with st.sidebar:
    st.header("Scope & Limits")
    start_url = st.text_input("Start URL", placeholder="https://example.com", help="Must be the root of your crawl scope.")
    allow_subdomains = st.checkbox("Allow subdomains", True)
    max_depth = st.number_input("Max depth", min_value=0, max_value=10, value=3)
    max_pages = st.number_input("Max pages", min_value=1, max_value=5000, value=500)
    concurrency = st.slider("Concurrency", min_value=1, max_value=32, value=8)
    respect_robots = st.checkbox("Respect robots.txt", value=True)
    rate_min = st.number_input("Rate delay min (sec)", min_value=0.0, max_value=3.0, value=0.1, step=0.1)
    rate_max = st.number_input("Rate delay max (sec)", min_value=0.0, max_value=5.0, value=0.5, step=0.1)
    ua = st.text_input("User-Agent", value=DEFAULT_UA)

    st.header("Authentication (Optional — for authorized targets)")
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

    run_button = st.button("Start Crawl")

if run_button:
    if not start_url:
        st.error("Please provide a Start URL.")
        st.stop()

    st.info("Crawling… This may take a while depending on limits and target size.")
    progress = st.empty()
    findings_placeholder = st.empty()

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

    crawler = Crawler(
        start_url=start_url.strip(),
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

    # Run crawler
    async def run_and_collect():
        await crawler.run()
        return crawler.findings

    findings = asyncio.run(run_and_collect())

    if not findings:
        st.warning("No pages crawled. Check scope/limits/auth or try again.")
        st.stop()

    df = to_dataframe(findings)
    st.success(f"Crawl finished. Pages visited: {len(df)}")

    # Summary
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Pages", len(df))
    with c2:
        st.metric("HTTP errors (>=400)", int((df['status'] >= 400).sum()))
    with c3:
        st.metric("Pages missing CSP", int((~df['hdr_csp']).sum()))
    with c4:
        st.metric("Password forms over HTTP", int(df['password_form_over_http'].sum()))

    # Table
    with st.expander("View Findings Table", expanded=True):
        view_cols = [
            "url","final_url","status","title","content_type","num_outlinks_internal",
            "num_outlinks_external","forms_count","has_password_form","password_form_over_http",
            "hdr_csp","hdr_xfo","hdr_hsts","hdr_xcto","hdr_refpol"
        ]
        st.dataframe(df[view_cols], use_container_width=True, hide_index=True)

    # Downloads
    cdl1, cdl2 = st.columns(2)
    with cdl1:
        st.download_button("⬇️ Download CSV", data=df.to_csv(index=False).encode("utf-8"), file_name="crawl_report.csv", mime="text/csv")
    with cdl2:
        st.download_button("⬇️ Download JSON", data=df.to_json(orient="records", indent=2).encode("utf-8"), file_name="crawl_report.json", mime="application/json")

    st.caption("Note: This tool is for authorized assessments within defined scope. Always obtain written permission.")
else:
    st.info("Configure scope/auth in the sidebar and click **Start Crawl**.")
``
