"""Campaign runner and statistics.

A campaign runs every applicable attack against one target
configuration, judges each transcript, and aggregates
attack success rate (ASR) overall and per category. Rates
are reported with Wilson score intervals: 8 successes in 10
trials is not "80% secure knowledge", it is a proportion
with a wide interval, and the report prints the interval
so nobody has to take the point estimate on faith.
"""
from __future__ import annotations

import math

from .attacks import attacks_for
from .judges import judge


def wilson(successes: int, n: int, z: float = 1.96) -> tuple:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n
                          + z * z / (4 * n * n)) / denom)
    return (max(0.0, centre - half), min(1.0, centre + half))


def run_attack(target, attack) -> dict:
    messages: list[dict] = []
    responses: list[str] = []
    for turn in attack.turns:
        messages.append({"role": "user", "content": turn})
        reply = target.chat(list(messages))
        responses.append(reply)
        messages.append({"role": "assistant", "content": reply})
    verdict = judge(attack.objective, responses)
    return {"attack_id": attack.id, "name": attack.name,
            "category": attack.category,
            "objective": attack.objective,
            "atlas": attack.atlas, "owasp": attack.owasp,
            **verdict, "responses": responses}


def _aggregate(rows: list[dict]) -> dict:
    n = len(rows)
    s = sum(1 for r in rows if r["success"])
    lo, hi = wilson(s, n)
    return {"attacks": n, "successes": s,
            "asr": (s / n) if n else 0.0,
            "asr_ci95": [round(lo, 3), round(hi, 3)],
            "refusals": sum(1 for r in rows if r["refused"])}


def run_campaign(target) -> dict:
    rows = [run_attack(target, a) for a in attacks_for(target)]
    by_category: dict[str, list[dict]] = {}
    for r in rows:
        by_category.setdefault(r["category"], []).append(r)
    return {"target": target.name, **_aggregate(rows),
            "by_category": {k: _aggregate(v)
                            for k, v in sorted(
                                    by_category.items())},
            "results": rows}
