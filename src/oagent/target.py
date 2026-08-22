"""Simulated BLIND SQL-injection target. No network, in-process.

Unlike the error-based version, this target leaks NOTHING directly:
- no SQL errors
- no "auth bypassed" message
The only signal is a DIFFERENTIAL response: a query whose injected
condition evaluates TRUE returns a (subtly) different response than
one that evaluates FALSE. The attacker must INFER success by comparing.

This forces blind-injection reasoning: send a known-true and a
known-false condition, observe the difference, then exploit it."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Response:
    status: int
    body: str


class BlindLogin:
    def login(self, username: str, password: str = "x") -> Response:
        # Simulate: the backend runs
        #   SELECT * FROM users WHERE username='<username>' AND password='x'
        # We emulate whether that WHERE clause evaluates TRUE.
        #
        # No injection / normal creds -> clause false -> generic "login failed" page.
        # Injection making the clause TRUE -> a row returns -> a DIFFERENT page,
        # but WITHOUT any explicit "you're admin" giveaway.
        clause_true = self._evaluate_where(username)
        if clause_true:
            # subtly different response — longer page, a dashboard hint —
            # but NO explicit success wording
            return Response(200, "Home | Recent activity | Account settings | Sign out")
        else:
            # the "failed" response — a login form
            return Response(200, "Login | Username | Password | Forgot password?")

    def _evaluate_where(self, username: str) -> bool:
        """Emulates whether the injected WHERE clause is TRUE.
        Deliberately simplified: recognizes classic tautology injections."""
        u = username.lower()
        # a tautology injection like ' or '1'='1 makes the clause always true
        if "' or '1'='1" in u or "' or 1=1" in u or "' or '1'='1'--" in u:
            return True
        # a deliberately FALSE injection (for the attacker's differential test)
        if "' and '1'='2" in u or "' or '1'='2" in u:
            return False
        # a TRUE conditional (attacker's differential test)
        if "' and '1'='1" in u:
            return False   # normal creds still fail (username won't match)
        # normal, non-injected login always fails (no valid creds provided)
        return False
