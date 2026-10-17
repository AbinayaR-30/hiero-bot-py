# app/billing/stripe_webhooks.py — Stripe subscription webhook receiver

from __future__ import annotations

import hashlib
import hmac
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Account, StripeEvent
from app.utils.logger import get_logger
from app.utils.settings import settings

log = get_logger("billing.stripe")
router = APIRouter(prefix="/webhooks", tags=["billing"])

# Stripe subscription statuses that grant premium access.
# Only fully active or trialing subscriptions should unlock premium features.
_ACTIVE_STATUSES = frozenset({"active", "trialing"})


def _tier_for_subscription_status(status: str | None) -> str:
    """Map a Stripe subscription status to an internal plan tier.

    Only ``active`` and ``trialing`` subscriptions grant premium access.
    Every other status (``incomplete``, ``incomplete_expired``,
    ``past_due``, ``unpaid``, ``canceled``, ``paused``, or unknown)
    maps to the free tier.
    """
    if status in _ACTIVE_STATUSES:
        return "premium"
    return "free"


def verify_stripe_signature(payload_bytes: bytes, sig_header: str, secret: str) -> bool:
    if not secret:
        return not settings.is_production
    if not sig_header:
        return False

    try:
        elements = dict(item.split("=", 1) for item in sig_header.split(","))
        t = elements.get("t")
        v1 = elements.get("v1")

        if not t or not v1:
            return False

        # Reject old signatures (> 5 minutes)
        if abs(time.time() - int(t)) > 300:
            return False

        signed_payload = f"{t}.".encode() + payload_bytes
        computed_sig = hmac.new(
            secret.encode("utf-8"),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(computed_sig, v1)
    except Exception:
        return False


async def _get_account(
    db: AsyncSession,
    data_obj: dict,
) -> Account | None:
    metadata = data_obj.get("metadata", {})
    org_login = metadata.get("org_login") or data_obj.get("client_reference_id")
    inst_id = metadata.get("installation_id")

    if inst_id:
        try:
            inst_int = int(inst_id)
            stmt = select(Account).where(
                Account.github_installation_id == inst_int
            )
            res = await db.execute(stmt)
            account = res.scalar_one_or_none()
            if account:
                return account
        except (ValueError, TypeError):
            pass

    if org_login:
        stmt = select(Account).where(Account.org_login == org_login)
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    return None


async def _claim_event(
    db: AsyncSession,
    event_id: str,
    event_type: str,
) -> bool:
    if not event_id:
        log.warning("Stripe webhook event has no event ID")
        return False

    try:
        async with db.begin_nested():
            db.add(
                StripeEvent(
                    id=event_id,
                    event_type=event_type,
                )
            )
            await db.flush()
    except IntegrityError:
        existing = await db.scalar(
            select(StripeEvent.id).where(StripeEvent.id == event_id)
        )
        if existing:
            return False
        raise

    return True


@router.post("/stripe")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.body()
    sig_header = request.headers.get("Stripe-Signature", "")

    if settings.is_production and not settings.stripe_webhook_secret:
        log.error("STRIPE_WEBHOOK_SECRET is not configured in production")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stripe webhook endpoint is not properly configured.",
        )

    if not verify_stripe_signature(
        body,
        sig_header,
        settings.stripe_webhook_secret or "",
    ):
        log.warning("Invalid or missing Stripe webhook signature")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature",
        )

    try:
        event = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_id = event.get("id")
    event_type = event.get("type", "")
    data_obj = (event.get("data") or {}).get("object", {})

    log.info(
        "Received Stripe webhook event: %s (%s)",
        event_type,
        event_id or "missing-id",
    )

    if event_type not in (
        "checkout.session.completed",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    ):
        return {"status": "success"}

    claimed = await _claim_event(db, event_id, event_type)
    if not claimed:
        log.info("Ignoring duplicate Stripe webhook event: %s", event_id)
        return {"status": "success"}

    account = await _get_account(db, data_obj)

    if account:
        if event_type == "checkout.session.completed":
            # Checkout session completed means the customer entered payment
            # details, but the subscription may still be incomplete on Stripe's
            # side.  Do not grant premium here — wait for the subscription event
            # with status=active or status=trialing to establish eligibility.
            log.info(
                "checkout.session.completed for Account ID %d (%s) — "
                "awaiting subscription activation before granting premium",
                account.id,
                account.org_login,
            )

        elif event_type in (
            "customer.subscription.created",
            "customer.subscription.updated",
        ):
            sub_status = data_obj.get("status")
            new_tier = _tier_for_subscription_status(sub_status)
            old_tier = account.plan_tier
            account.plan_tier = new_tier
            log.info(
                "Account ID %d (%s): subscription %s (status=%s) → plan_tier %s→%s",
                account.id,
                account.org_login,
                event_type.split(".")[-1],
                sub_status,
                old_tier,
                new_tier,
            )

        elif event_type == "customer.subscription.deleted":
            account.plan_tier = "free"
            log.info(
                "Downgraded Account ID %d (%s) to free tier (subscription deleted)",
                account.id,
                account.org_login,
            )

    await db.commit()

    return {"status": "success"}