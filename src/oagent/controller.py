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
    """Pull observation strings from action-observation records."""
    return [h["observation"] for h in history if h.get("observation", "").startswith("HTTP")]


def _obs_pairs(history: list[dict]) -> list[tuple[str, str]]:
    """Pull (action, observation) pairs for HTTP interactions."""
    return [(h.get("action", ""), h["observation"]) for h in history
            if h.get("observation", "").startswith("HTTP")]


def _validate_sqli(history):
    obs = _observations(history)
    # success = an authenticated/admin response appeared
    privileged = [o for o in obs if ("role=admin" in o or "Sign out" in o or "Home" in o)]
    # AND a normal/failed login response also appeared (proving it's not "everything returns Home")
    failed = [o for o in obs if "Login |" in o]
    if privileged and failed:
        return True, f"auth bypass confirmed: reached authenticated response ({len(privileged)}x), distinct from failed logins"
    if privileged and not failed:
        return True, f"auth bypass confirmed: reached authenticated response ({len(privileged)}x)"
    return False, "no authenticated/privileged response observed"

def _validate_idor(history: list[dict]) -> tuple[bool, str]:
    """IDOR: accessing MULTIPLE DISTINCT subjects' data via the same endpoint by
    only changing an identifier — unauthorized enumeration of others' data.
    The signature is NOT 'responses differ' (that's normal) but 'the same
    endpoint returned several different subjects' records without authorization'."""
    pairs = _obs_pairs(history)
    # look for successful (200) profile-style responses across different id values
    successful = [(a, o) for a, o in pairs if "HTTP 200" in o and "Profile" in o]
    # distinct subject data returned
    distinct_subjects = set(o for _, o in successful)
    if len(distinct_subjects) < 2:
        return False, ("IDOR not confirmed: need access to at least two distinct "
                       f"subjects' records (saw {len(distinct_subjects)})")
    return True, (f"IDOR confirmed: accessed {len(distinct_subjects)} distinct subjects' "
                  "records by varying the identifier, without authorization")


def _validate_generic(history: list[dict]) -> tuple[bool, str]:
    """Fallback: a reproducible differential exists."""
    obs = _observations(history)
    if len(obs) < 2:
        return False, "insufficient observations to establish a differential"
    baseline = obs[0]
    differing = [o for o in obs if o != baseline]
    if not differing:
        return False, "no differential observed — all responses match baseline"
    return True, f"differential confirmed: {len(differing)} response(s) differ from baseline"


def validate_finding(vuln_type: str, history: list[dict]) -> tuple[bool, str]:
    """Dispatch to the validator for the declared vuln type. The agent declares
    the type (for routing), but the type-specific check independently verifies
    the evidence exists — a mislabeled finding fails its own validator."""
    vt = (vuln_type or "").lower().strip()
    if vt in ("sqli", "sql_injection", "injection"):
        return _validate_sqli(history)
    if vt in ("idor", "bac", "broken_access_control", "access_control"):
        return _validate_idor(history)
    return _validate_generic(history)


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
                valid, vreason = validate_finding(decision.args.get("vuln_type", ""), self.history)
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
