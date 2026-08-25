"""Real HTTP target — a GENERIC client the agent uses to probe any endpoint.
Not vuln-specific: the agent decides method, path, and parameters itself.
Local testing only."""
from __future__ import annotations
from dataclasses import dataclass
import requests


@dataclass
class Response:
    status: int
    body: str


class HTTPTarget:
    def __init__(self, base: str = "http://127.0.0.1:5000"):
        self.base = base.rstrip("/")

    def request(self, method: str, path: str,
                params: dict | None = None,
                data: dict | None = None) -> Response:
        url = self.base + ("/" + path.lstrip("/"))
        try:
            r = requests.request(method.upper(), url,
                                 params=params or {},
                                 data=data or {},
                                 timeout=5)
            return Response(r.status_code, r.text.strip())
        except requests.RequestException as e:
            return Response(0, f"request failed: {e}")
