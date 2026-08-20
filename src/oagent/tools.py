"""Tools the agent can call. The brain chooses; these execute."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable

from oagent.target import SimulatedLogin


@dataclass
class ToolResult:
    ok: bool
    observation: str


class Tools:
    def __init__(self, target: SimulatedLogin):
        self.target = target
        self.findings: list[str] = []

    def try_login(self, username: str) -> ToolResult:
        resp = self.target.login(username)
        return ToolResult(ok=True, observation=f"HTTP {resp.status}: {resp.body}")

    def report_finding(self, description: str) -> ToolResult:
        self.findings.append(description)
        return ToolResult(ok=True, observation=f"FINDING RECORDED: {description}")

    def registry(self) -> dict[str, tuple[Callable, str]]:
        return {
            "try_login": (self.try_login,
                          "try_login(username): submit a username to the login endpoint"),
            "report_finding": (self.report_finding,
                               "report_finding(description): record a confirmed vulnerability"),
        }
