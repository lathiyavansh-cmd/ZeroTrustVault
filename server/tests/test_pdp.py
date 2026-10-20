import copy
import json
from pathlib import Path

import pytest

from ztv_server.pdp import LocalJsonPDP

POLICY = json.loads((Path(__file__).resolve().parents[2] / "seed" / "policy.json").read_text())


def attrs(**over):
    base = {
        "subject": {"id": "bob", "username": "bob", "role": "analyst", "department": "research", "clearance": 2, "employment_end": None, "employment_active": True, "mfa_fresh": False, "cert_revoked": False, "has_cert": True},
        "device": {"id": "d1", "posture": "registered", "jkt": "x", "registered": True},
        "resource": {"file_id": "f1", "owner_id": "alice", "department": "research", "classification": "CONFIDENTIAL", "level": 2},
        "environment": {"ip": "1.2.3.4", "geo": None, "hour_utc": 12, "risk_score": 10, "risk_level": "low", "mode": "zerotrustvault"},
        "grant": {"present": True, "rights": ["view", "download"], "expired": False, "downloads_left": 5, "posture_ok": True, "signature_ok": True},
        "action": {"intent": "download"},
    }
    for k, v in over.items():
        sec, _, key = k.partition("__")
        base[sec][key] = v
    return base


@pytest.fixture
def pdp():
    return LocalJsonPDP(copy.deepcopy(POLICY))


def test_default_deny_without_grant(pdp):
    d = pdp.evaluate(attrs(grant__present=False))
    assert d.effect == "DENY" and d.rule_id is None


def test_owner_permit(pdp):
    d = pdp.evaluate(attrs(subject__id="alice", grant__present=False))
    assert d.effect == "PERMIT" and d.rule_id == "permit-owner"


def test_grant_permit(pdp):
    d = pdp.evaluate(attrs())
    assert d.permit and d.rule_id == "permit-grant" and d.obligations == []


def test_clearance_too_low(pdp):
    assert pdp.evaluate(attrs(subject__clearance=1)).effect == "DENY"


def test_grant_expired(pdp):
    assert pdp.evaluate(attrs(grant__expired=True)).effect == "DENY"


def test_no_downloads_left(pdp):
    assert pdp.evaluate(attrs(grant__downloads_left=0)).effect == "DENY"


def test_intent_not_in_rights(pdp):
    assert pdp.evaluate(attrs(grant__rights=["view"])).effect == "DENY"
    assert pdp.evaluate(attrs(grant__rights=["view"], action__intent="view")).effect == "PERMIT"


def test_other_department_denied_but_auditor_ok(pdp):
    assert pdp.evaluate(attrs(subject__department="finance")).effect == "DENY"
    d = pdp.evaluate(attrs(subject__department="audit", subject__role="auditor"))
    assert d.effect == "PERMIT"


def test_employment_ended_overrides_owner(pdp):
    d = pdp.evaluate(attrs(subject__id="alice", subject__employment_active=False))
    assert d.effect == "DENY" and d.rule_id == "deny-employment-ended"


def test_bad_signature_denied(pdp):
    assert pdp.evaluate(attrs(grant__signature_ok=False)).effect == "DENY"


def test_step_up_obligation(pdp):
    d = pdp.evaluate(attrs(environment__risk_score=60))
    assert d.permit and "step_up_required" in d.obligations
    d = pdp.evaluate(attrs(environment__risk_score=60, subject__mfa_fresh=True))
    assert d.permit and d.obligations == []


def test_high_risk_denied(pdp):
    d = pdp.evaluate(attrs(environment__risk_score=85, subject__mfa_fresh=True))
    assert d.effect == "DENY" and d.rule_id == "deny-high-risk"


def test_revoked_cert_denied(pdp):
    assert pdp.evaluate(attrs(subject__cert_revoked=True)).effect == "DENY"


def test_admin_has_no_default_access(pdp):
    d = pdp.evaluate(attrs(subject__id="admin", subject__role="admin", subject__clearance=3, subject__department="it", grant__present=False))
    assert d.effect == "DENY"


def test_posture_not_satisfied(pdp):
    assert pdp.evaluate(attrs(grant__posture_ok=False)).effect == "DENY"


def test_secret_requires_trusted_device(pdp):
    a = attrs(resource__level=3, resource__classification="SECRET", subject__clearance=3)
    assert pdp.evaluate(a).effect == "DENY"
    a["device"]["posture"] = "trusted"
    assert pdp.evaluate(a).effect == "PERMIT"
