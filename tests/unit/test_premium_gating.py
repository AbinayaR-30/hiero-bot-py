# tests/unit/test_premium_gating.py — Verify is_premium helper

from app.billing.gating import is_premium
from app.db.models import Account


def test_is_premium_returns_true_for_premium():
    acc = Account(github_installation_id=1, org_login="ProOrg", plan_tier="premium")
    assert is_premium(acc) is True


def test_is_premium_returns_false_for_free():
    acc = Account(github_installation_id=2, org_login="FreeOrg", plan_tier="free")
    assert is_premium(acc) is False


def test_is_premium_returns_false_for_unknown_tier():
    acc = Account(github_installation_id=3, org_login="WeirdOrg", plan_tier="enterprise")
    assert is_premium(acc) is False