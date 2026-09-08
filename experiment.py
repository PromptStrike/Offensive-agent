"""A/B experiment: does action-observation attribution alone change outcomes?
Same model, same target, same prompt, same budget — toggle ONLY attribution."""
from oagent.http_target import HTTPTarget
from oagent.tools import Tools
from oagent.brain import LLMBrain
from oagent.controller import Controller

GOAL = "Find an authentication bypass on the /login endpoint"
RUNS = 5

def run_condition(attribution: bool) -> list:
    results = []
    for i in range(RUNS):
        agent = Controller(
            brain=LLMBrain(attribution=attribution),
            tools=Tools(HTTPTarget()),
            goal=GOAL,
            budget=25,
        )
        agent.run()
        # success = a finding was recorded; steps = how many the agent took
        succeeded = len(agent.tools.findings) > 0
        steps = len([h for h in agent.history if h.get("action", "").startswith("http_request")])
        results.append((succeeded, steps))
        print(f"\n### condition attribution={attribution} run {i+1}: "
              f"{'SUCCESS' if succeeded else 'FAIL'} in {steps} http actions\n")
    return results

if __name__ == "__main__":
    print("=" * 70, "\nCONDITION A: attribution OFF\n", "=" * 70)
    off = run_condition(False)
    print("=" * 70, "\nCONDITION B: attribution ON\n", "=" * 70)
    on = run_condition(True)

    print("\n\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print("attribution OFF:", off)
    print("attribution ON: ", on)
