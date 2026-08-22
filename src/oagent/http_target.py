"""Real HTTP target — makes actual requests to a running app.
Replaces the in-process simulation. This is a REAL attack over HTTP
against a locally-running vulnerable app."""
from __future__ import annotations
from dataclasses import dataclass
import requests


@dataclass
class Response:
    status: int
    body: str


class HTTPLogin:
    def __init__(self, url: str = "http://127.0.0.1:5000/login"):
        self.url = url

    def login(self, username: str, password: str = "x") -> Response:
        try:
            r = requests.post(self.url,
                              data={"username": username, "password": password},
                              timeout=5)
            return Response(r.status_code, r.text.strip())
        except requests.RequestException as e:
            return Response(0, f"request failed: {e}")
