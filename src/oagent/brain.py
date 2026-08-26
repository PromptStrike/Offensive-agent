"""The brain decides the next action. Pluggable: MockBrain (scripted) for
testing the scaffolding, LLMBrain (real) for a live model driving the attack.
Both implement the same Brain interface — swap freely."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass

import json
import os
import re
from groq import Groq


@dataclass
class Decision:
    reasoning: str
    tool: str
    args: dict


class Brain(ABC):
    @abstractmethod
    def decide(self, goal: str, tools_desc: str, history: list[str]) -> Decision:
        ...


class MockBrain(Brain):
    """Scripted reasoning that mimics an LLM working through an auth bypass.
    Deterministic — used to prove the scaffolding works before going live."""

    def decide(self, goal: str, tools_desc: str, history: list[dict]) -> Decision:
        joined = " ".join(history)
        if not history:
            return Decision("No info yet. Probe with a normal username.",
                            "try_login", {"username": "admin"})
        if "Invalid credentials" in joined and "SQL" not in joined:
            return Decision("Normal login failed. Test for SQL injection with a quote.",
                            "try_login", {"username": "admin'"})
        if "SQL syntax error" in joined and "auth bypassed" not in joined:
            return Decision("SQL error confirms injectable. Try comment bypass admin'--",
                            "try_login", {"username": "admin'--"})
        if "auth bypassed" in joined:
            return Decision("Bypass succeeded. Record the vulnerability.",
                            "report_finding",
                            {"description": "SQL injection auth bypass on /login via admin'--"})
        return Decision("No further actions.", "stop", {})


class LLMBrain(Brain):
    """Real LLM decision-maker. Same interface as MockBrain — swap freely."""

    def __init__(self, model: str = "openai/gpt-oss-120b"):
        self.client = Groq(api_key=os.environ["GROQ_API_KEY"])
        self.model = model

    def decide(self, goal: str, tools_desc: str, history: list[dict]) -> Decision:
        if not history:
            hist = "(nothing tried yet)"
        else:
            # history is a list of {action, observation} dicts.
            # render ACTION -> OBSERVATION pairs so the agent can attribute
            # which of its OWN actions caused which result.
            obs_strings = [h["observation"] for h in history
                           if h.get("observation", "").startswith("HTTP")]
            baseline = obs_strings[0] if obs_strings else None
            lines = []
            for h in history:
                action = h.get("action", "?")
                obs = h.get("observation", "?")
                if obs == baseline:
                    tag = "[baseline / no effect]"
                elif obs.startswith("HTTP") and obs != baseline:
                    tag = "[!! DIFFERS — THIS action produced a different result]"
                else:
                    tag = ""
                lines.append(f"- {action} -> {obs} {tag}")
            hist = "\n".join(lines)

        prompt = f"""You are a security testing agent probing a login endpoint.
GOAL: {goal}

AVAILABLE TOOLS:
{tools_desc}

WHAT YOU'VE OBSERVED SO FAR:
{hist}

You can submit any username and password you want. Decide the single next
action to work toward the goal. Observe how the endpoint responds and adapt
based on what you learn.

Respond with ONLY a JSON object, no other text:
{{"reasoning": "<why this action>", "tool": "http_request|report_finding|stop", "args": {{...}}}}
For http_request args use {{"method": "GET|POST", "path": "/...", "params": {{...}}, "data": {{...}}}}. For report_finding use {{"description": "...", "vuln_type": "sqli|idor"}}."""

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                temperature=0.0,
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = (resp.choices[0].message.content or "").strip()
            # strip markdown code fences if the model wrapped its JSON
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw).strip()
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not match:
                return Decision(f"could not parse response as JSON: {raw[:100]!r}",
                                "stop", {})
            obj = json.loads(match.group(0))
            return Decision(obj.get("reasoning", ""),
                            obj.get("tool", "stop"),
                            obj.get("args", {}) or {})
        except Exception as e:
            return Decision(f"error: {e}", "stop", {})
