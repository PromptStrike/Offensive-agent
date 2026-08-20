"""The controller runs the loop and enforces safety. Brain proposes;
controller disposes (after a safety check). Nothing executes unchecked."""
from __future__ import annotations
from dataclasses import dataclass, field

from oagent.brain import Brain
from oagent.tools import Tools


SAFE_TOOLS = {"try_login", "report_finding"}   # allowlist — deny by default


def safety_check(tool: str, args: dict) -> tuple[bool, str]:
    if tool not in SAFE_TOOLS:
        return False, f"tool '{tool}' not in allowlist"
    return True, "ok"


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

            fn, _ = registry[decision.tool]
            result = fn(**decision.args)
            print(f"  ACT: {decision.tool}({decision.args})")
            print(f"  OBSERVE: {result.observation}")
            self.history.append(result.observation)

            if decision.tool == "report_finding":
                print("\n" + "=" * 60 + "\nGOAL ACHIEVED. Findings:")
                for f in self.tools.findings:
                    print("  -", f)
                break
        else:
            print("\nBudget exhausted without achieving goal.")
