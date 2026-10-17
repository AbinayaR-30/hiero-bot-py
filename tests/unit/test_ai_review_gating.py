"""AI code review must be skipped for free accounts."""

import types
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.workflows.pullrequest import PullRequestWorkflow


def _make_ctx(plan_tier: str) -> dict:
    cfg = MagicMock()
    cfg.workflows.pull_request.enabled = True
    gates = cfg.workflows.pull_request.quality_gates
    gates.require_linked_issue = False
    gates.require_tests = False
    gates.require_dco = False
    gates.require_gpg_signature = False
    gates.max_files_changed = 0
    gates.allowed_branch_pattern = ""
    gates.require_changelog_entry = False
    cfg.workflows.pull_request.ai_review.enabled = True
    cfg.workflows.pull_request.reviewer_recommendation = False
    return {
        "owner": "o", "repo": "r", "installation_id": 1,
        "config": cfg, "db": AsyncMock(),
        "account": types.SimpleNamespace(plan_tier=plan_tier),
    }


PR = {"pull_request": {"number": 1, "draft": False, "user": {"login": "author"}, "head": {"sha": "abc"}, "body": ""}}


def _make_wf():
    gh = MagicMock()
    gh.list_issue_comments = AsyncMock(return_value=[])
    gh.post_comment = AsyncMock()
    gh.add_label = AsyncMock()
    gh.remove_label = AsyncMock()
    gh.list_pr_files = AsyncMock(return_value=[])
    wf = PullRequestWorkflow(gh)
    wf._ai.close = AsyncMock()  # prevent real AIReviewer.close() call
    return wf


@pytest.mark.asyncio
async def test_free_account_does_not_trigger_ai_review():
    """Even when ai_review.enabled=True, free accounts must not get AI reviews."""
    called = []

    async def _fake(*_a, **_k):
        called.append(True)

    wf = _make_wf()
    wf._run_ai_review = _fake  # instance-level override
    await wf.handle_pr_opened(_make_ctx("free"), PR, action="opened")
    assert not called, "_run_ai_review must not be called for a free account"


@pytest.mark.asyncio
async def test_premium_account_triggers_ai_review():
    """Premium accounts with ai_review.enabled=True must get AI reviews."""
    called = []

    async def _fake(*_a, **_k):
        called.append(True)

    wf = _make_wf()
    wf._run_ai_review = _fake  # instance-level override
    await wf.handle_pr_opened(_make_ctx("premium"), PR, action="opened")
    assert called, "_run_ai_review was not called for a premium account"
