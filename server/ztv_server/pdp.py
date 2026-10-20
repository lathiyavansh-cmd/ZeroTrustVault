"""Policy Decision Point: hybrid RBAC + ABAC over a JSON policy (CONTRACT §11).

Evaluation: deny-overrides (any matching DENY rule wins), then the first matching PERMIT,
else default DENY.  Obligations: risk_score >= 60 -> step_up_required unless subject.mfa_fresh;
risk_score >= 85 -> DENY (also expressed as a policy rule).

`PolicyDecisionPoint` is the seam: `LocalJsonPDP` evaluates in-process, `OpaPDP` forwards the
attribute document to Open Policy Agent (`POST {OPA_URL}/v1/data/ztv/decision`).
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

STEP_UP_RISK = 60
DENY_RISK = 85
CLASSIFICATION_LEVELS = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "SECRET": 3}


@dataclass
class Decision:
    effect: str  # PERMIT | DENY
    rule_id: str | None = None
    reason: str = ""
    obligations: list[str] = field(default_factory=list)

    @property
    def permit(self) -> bool:
        return self.effect == "PERMIT"

    def as_dict(self) -> dict:
        return {"effect": self.effect, "rule_id": self.rule_id, "reason": self.reason, "obligations": list(self.obligations)}


def resolve(attrs: dict, path: Any) -> Any:
    """Resolve a dotted attribute path against the attribute document; non-strings are literals."""
    if not isinstance(path, str):
        return path
    cur: Any = attrs
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _is_ref(attrs: dict, value: Any) -> bool:
    if not isinstance(value, str) or "." not in value:
        return False
    head = value.split(".", 1)[0]
    return head in attrs


def condition_holds(attrs: dict, cond: dict) -> bool:
    op = cond.get("op", "==")
    left = resolve(attrs, cond.get("attr"))
    raw = cond.get("value")
    right = resolve(attrs, raw) if _is_ref(attrs, raw) else raw
    try:
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == "exists":
            return left is not None
        if op == "true":
            return left is True
        if op == "false":
            return left is False
        if op == "in":
            return right is not None and left in right
        if op == "not_in":
            return right is None or left not in right
        if op == "contains":
            return left is not None and right in left
        if left is None or right is None:
            return False
        if op == ">=":
            return left >= right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        if op == "<":
            return left < right
    except TypeError:
        return False
    return False


def rule_matches(attrs: dict, rule: dict) -> bool:
    all_conds = rule.get("all", [])
    any_conds = rule.get("any", [])
    if not all(condition_holds(attrs, c) for c in all_conds):
        return False
    if any_conds and not any(_group_holds(attrs, c) for c in any_conds):
        return False
    return True


def _group_holds(attrs: dict, c: dict) -> bool:
    if "all" in c or "any" in c:
        return rule_matches(attrs, c)
    return condition_holds(attrs, c)


class PolicyDecisionPoint(abc.ABC):
    @abc.abstractmethod
    async def decide(self, attrs: dict) -> Decision: ...


class LocalJsonPDP(PolicyDecisionPoint):
    def __init__(self, policy: dict | None = None):
        self.policy = policy or {"rules": []}

    def set_policy(self, policy: dict) -> None:
        self.policy = policy

    def evaluate(self, attrs: dict) -> Decision:
        rules = self.policy.get("rules", [])
        for rule in rules:
            if rule.get("effect") == "DENY" and rule_matches(attrs, rule):
                return Decision("DENY", rule.get("id"), rule.get("description") or "deny rule matched")
        env = attrs.get("environment", {})
        risk = int(env.get("risk_score") or 0)
        if risk >= DENY_RISK:
            return Decision("DENY", "builtin-risk-deny", f"risk score {risk} >= {DENY_RISK}")
        for rule in rules:
            if rule.get("effect") == "PERMIT" and rule_matches(attrs, rule):
                obligations: list[str] = []
                if risk >= STEP_UP_RISK and not attrs.get("subject", {}).get("mfa_fresh"):
                    obligations.append("step_up_required")
                return Decision("PERMIT", rule.get("id"), rule.get("description") or "permit rule matched", obligations)
        return Decision("DENY", None, "no rule permitted the request (default deny)")

    async def decide(self, attrs: dict) -> Decision:
        return self.evaluate(attrs)


class OpaPDP(PolicyDecisionPoint):
    """Forwards the attribute document to OPA; expects `{"result": {"effect","rule_id","reason","obligations"}}`."""

    def __init__(self, opa_url: str, fallback: PolicyDecisionPoint | None = None, timeout: float = 2.0):
        self.url = opa_url.rstrip("/") + "/v1/data/ztv/decision"
        self.fallback = fallback
        self.timeout = timeout

    async def decide(self, attrs: dict) -> Decision:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(self.url, json={"input": attrs})
                r.raise_for_status()
                res = r.json().get("result") or {}
        except Exception as e:  # noqa: BLE001
            if self.fallback is not None:
                d = await self.fallback.decide(attrs)
                d.reason = f"opa unavailable ({e}); local decision: {d.reason}"
                return d
            return Decision("DENY", "opa-error", f"OPA unavailable: {e}")
        effect = "PERMIT" if res.get("effect") == "PERMIT" or res.get("allow") is True else "DENY"
        return Decision(effect, res.get("rule_id"), res.get("reason", ""), list(res.get("obligations") or []))


def level_of(classification: str) -> int:
    return CLASSIFICATION_LEVELS.get(str(classification).upper(), 3)
