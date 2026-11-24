import re
import time
import httpx
from typing import Dict, Any
from html.parser import HTMLParser


class _EndpointHTMLParser(HTMLParser):
    """Parses h1-h3 headings and form inputs (input, select, textarea) from HTML."""
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None
        self.headings = []
        self._in_heading = False

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag in ("h1", "h2", "h3"):
            self._in_heading = True
        elif tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": []
            }
        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            self._current_form["inputs"].append({
                "tag": tag,
                "name": attr_dict.get("name"),
                "type": attr_dict.get("type", "text"),
                "value": attr_dict.get("value")
            })

    def handle_endtag(self, tag):
        if tag in ("h1", "h2", "h3"):
            self._in_heading = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        text = data.strip()
        if self._in_heading and text:
            self.headings.append(text)


class DVWAClient:
    def __init__(self, base_url: str = "http://localhost/DVWA", security_level: str = "low"):
        # Trailing slash ensures httpx preserves subpaths like /DVWA/
        self.base_url = base_url.rstrip("/") + "/"
        self.security_level = security_level
        self.client = httpx.Client(base_url=self.base_url, follow_redirects=False, timeout=15.0)

    def _clean_path(self, endpoint: str) -> str:
        """Strips leading slashes so httpx resolves paths relative to self.base_url."""
        return endpoint.lstrip("/")

    def _extract_user_token(self, html: str) -> str | None:
        match = re.search(
            r"<input[^>]*name=['\"]user_token['\"][^>]*value=['\"]([a-f0-9]+)['\"]|"
            r"<input[^>]*value=['\"]([a-f0-9]+)['\"][^>]*name=['\"]user_token['\"]",
            html,
            re.IGNORECASE
        )
        if not match:
            return None
        return match.group(1) or match.group(2)

    def _set_security_cookie(self):
        """Removes any server-issued 'security' cookies before setting the target level."""
        to_delete = [c for c in self.client.cookies.jar if c.name == "security"]
        for cookie in to_delete:
            self.client.cookies.jar.clear(domain=cookie.domain, path=cookie.path, name="security")
        self.client.cookies.set("security", self.security_level, path="/")

    def _get_safe_cookies(self) -> Dict[str, str]:
        """Safely extracts cookies without raising CookieConflict on duplicate path scopes."""
        return {c.name: c.value for c in self.client.cookies.jar}

    def profile_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """Blindly inspects an endpoint to extract its structural state, forms, and parameters."""
        clean_ep = self._clean_path(endpoint)
        response = self.client.get(clean_ep)

        parser = _EndpointHTMLParser()
        parser.feed(response.text)

        functional_forms = []
        for form in parser.forms:
            filtered_inputs = [
                inp for inp in form["inputs"]
                if inp["name"] and inp["name"] not in ("user_token",)
            ]
            if filtered_inputs:
                functional_forms.append({
                    "action": form["action"],
                    "method": form["method"],
                    "inputs": filtered_inputs
                })

        return {
            "endpoint": clean_ep,
            "status_code": response.status_code,
            "headings": parser.headings,
            "forms": functional_forms,
            "active_cookies": self._get_safe_cookies()
        }

    def authenticate(self, username: str = "gordonb", password: str = "abc123") -> bool:
        """Logs into DVWA and establishes an authenticated PHPSESSID."""
        login_page = self.client.get(self._clean_path("login.php"))
        token = self._extract_user_token(login_page.text)

        payload = {
            "username": username,
            "password": password,
            "Login": "Login",
        }
        if token:
            payload["user_token"] = token

        self.client.post(self._clean_path("login.php"), data=payload)
        
        # Clear server-assigned security cookie before enforcing our level
        self._set_security_cookie()

        verify = self.client.get(self._clean_path("index.php"))
        return verify.status_code == 200 and "Logout" in verify.text

    def send_audit_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Dict[str, Any] | None = None,
        data: Dict[str, Any] | None = None,
        auto_csrf: bool = True
    ) -> Dict[str, Any]:
        """Executes a single HTTP interaction and captures deterministic telemetry."""
        clean_ep = self._clean_path(endpoint)

        if auto_csrf and method.upper() == "POST":
            probe = self.client.get(clean_ep)
            token = self._extract_user_token(probe.text)
            if token and data is not None and "user_token" not in data:
                data["user_token"] = token

        start = time.perf_counter()
        response = self.client.request(
            method=method.upper(),
            url=clean_ep,
            params=params,
            data=data
        )
        latency_ms = (time.perf_counter() - start) * 1000

        return {
            "endpoint": clean_ep,
            "method": method.upper(),
            "status_code": response.status_code,
            "redirect_location": response.headers.get("location"),
            "latency_ms": round(latency_ms, 2),
            "cookies": self._get_safe_cookies(),
            "body_snippet": response.text
        }