import re
import time
import httpx
from typing import Dict, Any, Optional

class DVWAClient:
    def __init__(self, base_url: str = "http://localhost/DVWA", security_level: str = "low"):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, follow_redirects=False, timeout=15.0)
        self.client.cookies.set("security", security_level)

    def _extract_user_token(self, html: str) -> Optional[str]:
        match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", html, re.IGNORECASE)
        return match.group(1) if match else None

    def authenticate(self, username: str = "gordonb", password: str = "abc123") -> bool:
        """Logs into DVWA and establishes an authenticated PHPSESSID."""
        login_page = self.client.get("/login.php")
        print(f"[DEBUG] GET /login.php -> Status: {login_page.status_code}, Location: {login_page.headers.get('location')}")
        
        token = self._extract_user_token(login_page.text)
        print(f"[DEBUG] Extracted CSRF user_token: {token}")

        payload = {
            "username": username,
            "password": password,
            "Login": "Login",
        }
        if token:
            payload["user_token"] = token

        res = self.client.post("/login.php", data=payload)
        print(f"[DEBUG] POST /login.php -> Status: {res.status_code}, Location: {res.headers.get('location')}")
        print(f"[DEBUG] Cookies: {dict(self.client.cookies)}")
        
        # Verify by requesting index.php directly
        verify = self.client.get("/index.php")
        is_logged_in = verify.status_code == 200 and "Logout" in verify.text
        print(f"[DEBUG] Authenticated check (/index.php): {is_logged_in}")
        return is_logged_in

    def send_audit_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        auto_csrf: bool = True
    ) -> Dict[str, Any]:
        """Executes a single HTTP interaction and captures deterministic telemetry."""
        if auto_csrf and method.upper() == "POST":
            probe = self.client.get(endpoint)
            token = self._extract_user_token(probe.text)
            if token and data is not None and "user_token" not in data:
                data["user_token"] = token

        start = time.perf_counter()
        response = self.client.request(
            method=method.upper(),
            url=endpoint,
            params=params,
            data=data
        )
        latency_ms = (time.perf_counter() - start) * 1000

        return {
            "endpoint": endpoint,
            "method": method.upper(),
            "status_code": response.status_code,
            "redirect_location": response.headers.get("location"),
            "latency_ms": round(latency_ms, 2),
            "cookies": dict(self.client.cookies),
            "body_snippet": response.text[:1500]
        }