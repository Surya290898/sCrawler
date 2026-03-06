# Make the crawler directory a proper Python package and expose common symbols.

from .auth import AuthConfig, apply_cookie_header, perform_form_login, build_session_kwargs
from .crawl import Crawler, DEFAULT_UA
from .robots import load_robots, can_fetch, parse_sitemap, fetch_text
from .report import (
    PageFinding, Issue,
    to_dataframe, to_csv, to_json,
    issues_to_dataframe, issues_to_csv, issues_to_json,
    overall_site_score,
)
# If you added the unique findings helpers, they will be available from .report as well.
