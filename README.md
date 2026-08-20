# oagent — Autonomous Offensive Security Agent

A minimal autonomous offensive security agent: a real LLM drives an
attack loop (perceive → reason → act → observe → adapt) against a
target, bounded by a safety layer and an action budget.

## What it does

The agent is given a goal, a set of tools, and a target. An LLM "brain"
proposes each next action; a controller enforces a safety allowlist
before any action executes, records observations, and stops on success
or budget exhaustion.

**Architecture:**
- `Controller` — the loop + safety enforcement (brain proposes, controller disposes)
- `Brain` — pluggable decision-maker (`MockBrain` for deterministic testing, `LLMBrain` for a real model)
- `Tools` — the actions the agent can take
- `Memory` — observation history
- `Target` — a **simulated, in-process** vulnerable system (no network)

## Important — simulated target only

This agent attacks a **simulated, in-process target** (`SimulatedLogin`)
for research and educational purposes. It does not attack real systems,
does not open network connections, and is not intended for use against
any system without explicit authorization.

## Run

```bash
pip install -e .
export GROQ_API_KEY="your-key"
PYTHONPATH=src python run.py
```

## Status

Early research prototype. Roadmap: finding-validation layer (verify
exploits via differential re-demonstration, not just the model's claim),
stop-condition / stuck-detection, and additional attack scenarios
(indirect prompt injection via compromised tool output).
