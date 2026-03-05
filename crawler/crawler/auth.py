import aiohttp
from yarl import URL

class AuthConfig:
    def __init__(
        self,
        basic_user: str | None = None,
        basic_pass: str | None = None,
        cookie_string: str | None = None,
        login_url: str | None = None,
        username_field: str | None = None,
        password_field: str | None = None,
        username_value: str | None = None,
        password_value: str | None = None,
        extra_fields: dict | None = None,
    ):
        self.basic_user = basic_user
        self.basic_pass = basic_pass
        self.cookie_string = cookie_string
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.username_value = username_value
        self.password_value = password_value
        self.extra_fields = extra_fields or {}

def apply_cookie_header(headers: dict, cookie_string: str | None) -> dict:
    if cookie_string:
        headers = dict(headers)
        headers["Cookie"] = cookie_string
    return headers

async def perform_form_login(session: aiohttp.ClientSession, cfg: AuthConfig) -> None:
    """
    Perform a login POST to obtain session cookies.
    This requires explicit permission and correct field names.
    """
    if not (cfg.login_url and cfg.username_field and cfg.password_field and cfg.username_value and cfg.password_value):
        return
    data = {
        cfg.username_field: cfg.username_value,
        cfg.password_field: cfg.password_value,
        **cfg.extra_fields
    }
    # Fetch login page first (for CSRF cookies if any)
    try:
        async with session.get(cfg.login_url, allow_redirects=True) as _:
            pass
    except Exception:
        return
    try:
        async with session.post(cfg.login_url, data=data, allow_redirects=True) as resp:
            _ = await resp.text()  # consume
    except Exception:
        return

def build_session_kwargs(cfg: AuthConfig) -> dict:
    kwargs: dict = {}
    if cfg.basic_user and cfg.basic_pass:
        kwargs["auth"] = aiohttp.BasicAuth(cfg.basic_user, cfg.basic_pass)
    return kwargs
