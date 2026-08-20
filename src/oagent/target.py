"""Simulated vulnerable login. No network, no port — pure in-process.
Vulnerable to SQL-injection auth bypass via admin'-- payload."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Response:
    status: int
    body: str


class SimulatedLogin:
    def login(self, username: str, password: str = "x") -> Response:
        if "'--" in username or "' --" in username:
            return Response(200, "Welcome, admin! (auth bypassed)")
        if "'" in username:
            return Response(500, "SQL syntax error near '" + username + "'")
        return Response(401, "Invalid credentials")
