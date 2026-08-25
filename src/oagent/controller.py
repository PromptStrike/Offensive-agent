"""The controller runs the loop and enforces safety. Brain proposes;
controller disposes (after a safety check). Nothing executes unchecked.

History records ACTION-OBSERVATION PAIRS (not bare observations), so the
agent can attribute which of its own actions caused which result. Findings
are VALIDATED before acceptance (a reproducible differential must exist),
and repeated failing actions are flagged for stuck-detection."""
from __future__ import annotations
from dataclasses import dataclass, field

from oagent.brain import Brain
from oagent.tools import Tools

SAFE_TOOLS = {"http_request", "report_finding"}   # allowlist — deny by default


def safety_check(tool: str, args: dict) -> tuple[bool, str]:
    if tool not in SAFE_TOOLS:
        return False, f"tool '{tool}' not in allowlist"
    return True, "ok"


def _observations(history: list[dict]) -> list[str]:
    """Pull the observation strings from action-observation records."""
    return [h["observation"] for h in history if h.get("observation", "").startswith("HTTP")]


def validate_finding(history: list[dict]) -> tuple[bool, str]:
    """Computational check: is there independent evidence for the finding?
    Require a reproducible DIFFERENTIAL — at least one observed response that
    differs from the baseline (first HTTP observation). Confirms the exploit
    produced an observable effect rather than trusting the brain's claim."""
    obs = _observations(history)
    if len(obs) < 2:
        return False, "insufficient observations to establish a differential"
    baseline = obs[0]
    differing = [o for o in obs if o != baseline]
    if not differing:
        return False, "no differential observed — all responses match baseline"
    return True, f"differential confirmed: {len(differing)} response(s) differ from baseline"


@dataclass
class Controller:
    brain: Brain
    tools: Tools
    goal: str
    budget: int = 25
    history: list[dict] = field(default_factory=list)

    def _already_tried(self, action: str) -> bool:
        """Stuck-detection: has this exact action already been tried and
        produced a NON-differential (baseline) result?"""
        obs = _observations(self.history)
        baseline = obs[0] if obs else None
        for h in self.history:
            if h.get("action") == action:
                # tried before; did it produce only a baseline (failed) result?
                if baseline is not None and h.get("observation") == baseline:
                    return True
        return False

    def run(self) -> None:
        print(f"GOAL: {self.goal}\n" + "=" * 60)
        registry = self.tools.registry()
        tools_desc = "\n".join(d for _, d in registry.values())

        for step in range(1, self.budget + 1):
            decision = self.brain.decide(self.goal, tools_desc, self.history)
            print(f"\n[step {step}] THINK: {decision.reasoning}")

            if decision.tool == "stop":
                print("BRAIN chose to stop.")
                break

            allowed, reason = safety_check(decision.tool, decision.args)
            if not allowed:
                print(f"  SAFETY BLOCKED: {reason}")
                self.history.append({"action": f"{decision.tool}({decision.args})",
                                     "observation": f"[blocked: {reason}]"})
                continue

            action_str = f"{decision.tool}({decision.args})"

            # STUCK-DETECTION: refuse to repeat an action that already failed
            if decision.tool == "http_request" and self._already_tried(action_str):
                print(f"  STUCK: '{action_str}' already tried and failed — try something DIFFERENT")
                self.history.append({"action": action_str,
                                     "observation": "[repeat of a previously-failed action — skipped]"})
                continue

            # VALIDATION GATE: before accepting a finding, independently verify evidence
            if decision.tool == "report_finding":
                valid, vreason = validate_finding(self.history)
                if not valid:
                    print(f"  FINDING REJECTED: {vreason}")
                    self.history.append({"action": action_str,
                                         "observation": f"[finding rejected: {vreason}]"})
                    continue
                print(f"  FINDING VALIDATED: {vreason}")

            fn, _ = registry[decision.tool]
            result = fn(**decision.args)
            print(f"  ACT: {decision.tool}({decision.args})")
            print(f"  OBSERVE: {result.observation}")
            self.history.append({"action": action_str, "observation": result.observation})

            if decision.tool == "report_finding":
                print("\n" + "=" * 60 + "\nGOAL ACHIEVED (validated). Findings:")
                for f in self.tools.findings:
                    print("  -", f)
                break
        else:
            print("\nBudget exhausted without achieving goal.")
