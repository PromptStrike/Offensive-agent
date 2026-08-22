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

    def decide(self, goal: str, tools_desc: str, history: list[str]) -> Decision:
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

    def decide(self, goal: str, tools_desc: str, history: list[str]) -> Decision:
        if not history:
            hist = "(nothing tried yet)"
        else:
            baseline = history[0]
            lines = []
            for i, h in enumerate(history):
                if i == 0:
                    lines.append(f"- [baseline] {h}")
                elif h != baseline:
                    lines.append(f"- [!! DIFFERS from baseline] {h}")
                else:
                    lines.append(f"- [same as baseline] {h}")
            hist = "\n".join(lines)

        prompt = f"""You are an offensive security agent testing a login endpoint.

GOAL: {goal}

AVAILABLE TOOLS:
{tools_desc}

WHAT YOU'VE OBSERVED SO FAR:
{hist}

Decide the single next action. Think like a pentester: probe, observe how
responses change, and adapt.

Important: the target may NOT announce success directly — there may be no error
message and no explicit "success" text. Success can be IMPLICIT. If a payload
produces a response that DIFFERS from a normal/baseline request, that difference
is itself evidence the payload worked. Compare your observations: establish a
baseline (a normal request), then look for payloads that produce a DIFFERENT
response. A consistent, reproducible difference between an injected request and
the baseline is a confirmed finding — do not keep re-testing the same payload
once you have already seen the differential.BEFORE choosing a new action, review the observations above: if any is marked
"DIFFERS from baseline", you have ALREADY produced a differential — that is your
confirmed finding. Report it immediately rather than continuing to probe.

When you have confirmed a vulnerability (including via a response differential),
use report_finding. If nothing left to do, use "stop".

Respond with ONLY a JSON object, no other text:
{{"reasoning": "<why this action>", "tool": "try_login|report_finding|stop", "args": {{...}}}}
For try_login args use {{"username": "..."}}. For report_finding use {{"description": "..."}}."""

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                temperature=0.0,
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp.choices[0].message.content.strip()
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            obj = json.loads(match.group(0))
            return Decision(obj.get("reasoning", ""),
                            obj.get("tool", "stop"),
                            obj.get("args", {}))
        except Exception as e:
            return Decision(f"error: {e}", "stop", {})
