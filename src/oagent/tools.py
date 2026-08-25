"""Tools the agent can call. The brain chooses; these execute.
The interaction tool is GENERIC (http_request) — not vuln-specific — so the
same agent can probe any endpoint for any vulnerability class."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable

from oagent.http_target import HTTPTarget


@dataclass
class ToolResult:
    ok: bool
    observation: str


class Tools:
    def __init__(self, target: HTTPTarget):
        self.target = target
        self.findings: list[str] = []

    def http_request(self, method: str, path: str,
                     params: dict | None = None,
                     data: dict | None = None) -> ToolResult:
        resp = self.target.request(method, path, params=params, data=data)
        return ToolResult(ok=True, observation=f"HTTP {resp.status}: {resp.body}")

    def report_finding(self, description: str, vuln_type: str = "") -> ToolResult:
        self.findings.append(f"[{vuln_type}] {description}" if vuln_type else description)
        return ToolResult(ok=True, observation=f"FINDING RECORDED: {description}")

    def registry(self) -> dict[str, tuple[Callable, str]]:
        return {
            "http_request": (self.http_request,
                             "http_request(method, path, params, data): send an HTTP request. "
                             "method=GET/POST, path like '/login' or '/profile', "
                             "params={} for query string, data={} for form body"),
            "report_finding": (self.report_finding,
                               "report_finding(description, vuln_type): record a confirmed "
                               "vulnerability. vuln_type is one of: sqli, idor"),
        }
