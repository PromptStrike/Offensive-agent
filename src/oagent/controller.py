"""The controller runs the loop and enforces safety. Brain proposes;
controller disposes (after a safety check). Nothing executes unchecked.

Findings are VALIDATED before acceptance: the controller confirms there is
independent evidence in the observation history (a reproducible differential
between a baseline and an exploit response) rather than trusting the brain's
claim. Against the deterministic mock this always holds; against a real target
this layer is what catches false/hallucinated findings."""
from __future__ import annotations
from dataclasses import dataclass, field

from oagent.brain import Brain
from oagent.tools import Tools

SAFE_TOOLS = {"try_login", "report_finding"}   # allowlist — deny by default


def safety_check(tool: str, args: dict) -> tuple[bool, str]:
    if tool not in SAFE_TOOLS:
        return False, f"tool '{tool}' not in allowlist"
    return True, "ok"


def validate_finding(history: list[str]) -> tuple[bool, str]:
    """Computational check: is there independent evidence for the finding?
    We require a reproducible DIFFERENTIAL — at least one observed response
    that differs from the baseline (first observation). This confirms the
    exploit produced an observable effect, rather than trusting the brain's
    claim. (For a real target this would re-run the exploit + baseline to
    confirm the differential is stable, not a fluke.)"""
    observations = [h for h in history if h.startswith("HTTP")]
    if len(observations) < 2:
        return False, "insufficient observations to establish a differential"
    baseline = observations[0]
    differing = [o for o in observations if o != baseline]
    if not differing:
        return False, "no differential observed — all responses match baseline"
    return True, f"differential confirmed: {len(differing)} response(s) differ from baseline"


@dataclass
class Controller:
    brain: Brain
    tools: Tools
    goal: str
    budget: int = 8
    history: list[str] = field(default_factory=list)

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
                self.history.append(f"[blocked: {decision.tool}]")
                continue

            # VALIDATION GATE: before accepting a finding, independently verify evidence
            if decision.tool == "report_finding":
                valid, vreason = validate_finding(self.history)
                if not valid:
                    print(f"  FINDING REJECTED: {vreason}")
                    self.history.append(f"[finding rejected: {vreason}]")
                    continue   # don't accept; let the agent keep working
                print(f"  FINDING VALIDATED: {vreason}")

            fn, _ = registry[decision.tool]
            result = fn(**decision.args)
            print(f"  ACT: {decision.tool}({decision.args})")
            print(f"  OBSERVE: {result.observation}")
            self.history.append(result.observation)

            if decision.tool == "report_finding":
                print("\n" + "=" * 60 + "\nGOAL ACHIEVED (validated). Findings:")
                for f in self.tools.findings:
                    print("  -", f)
                break
        else:
            print("\nBudget exhausted without achieving goal.")
