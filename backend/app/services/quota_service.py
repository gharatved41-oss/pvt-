"""Daily Scan Quota and Access Clearance Service for SentinelX.
Enforces:
- Google / Apple authenticated users: Strictly 3 link analyses per day (24-hour cycle).
- Platform Developers: Unlimited clearance and real-time threat intelligence access.
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from backend.app.models.database import UserDailyQuota
from backend.app.core.logging import logger

STANDARD_USER_DAILY_LIMIT = 3


class QuotaService:
    @staticmethod
    def _get_today_str() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def get_user_quota(
        self,
        db: Session,
        user_identifier: str,
        user_role: str = "user"
    ) -> Dict[str, Any]:
        """
        Retrieves the current day's quota usage for a given user identifier.
        """
        is_developer = (user_role.lower() == "developer")
        today = self._get_today_str()

        # Clean identifier
        identifier = (user_identifier or "anonymous").strip().lower()

        record = db.query(UserDailyQuota).filter(
            UserDailyQuota.user_identifier == identifier,
            UserDailyQuota.date_str == today
        ).first()

        used = record.scan_count if record else 0

        if is_developer:
            return {
                "user_identifier": identifier,
                "role": "developer",
                "daily_limit": None,
                "used_today": used,
                "remaining": 999999,
                "unlimited": True,
                "can_analyze": True,
                "reset_cycle": "UNLIMITED_CLEARANCE"
            }

        limit = STANDARD_USER_DAILY_LIMIT
        remaining = max(0, limit - used)
        can_analyze = (used < limit)

        return {
            "user_identifier": identifier,
            "role": "user",
            "daily_limit": limit,
            "used_today": used,
            "remaining": remaining,
            "unlimited": False,
            "can_analyze": can_analyze,
            "reset_cycle": f"{today} 23:59:59 UTC"
        }

    def check_and_consume_quota(
        self,
        db: Session,
        user_identifier: str,
        user_role: str = "user"
    ) -> Dict[str, Any]:
        """
        Checks if the user has available quota for today and increments the count.
        Raises HTTP 429 if Google/Apple user has exceeded 3 links for the day.
        """
        is_developer = (user_role.lower() == "developer")
        today = self._get_today_str()
        identifier = (user_identifier or "anonymous").strip().lower()

        record = db.query(UserDailyQuota).filter(
            UserDailyQuota.user_identifier == identifier,
            UserDailyQuota.date_str == today
        ).first()

        if not record:
            record = UserDailyQuota(
                user_identifier=identifier,
                user_role=user_role,
                date_str=today,
                scan_count=0
            )
            db.add(record)
            db.flush()

        if not is_developer:
            if record.scan_count >= STANDARD_USER_DAILY_LIMIT:
                logger.warning(
                    f"Quota exceeded for user {identifier} ({record.scan_count}/{STANDARD_USER_DAILY_LIMIT})"
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Daily analysis limit reached ({record.scan_count}/{STANDARD_USER_DAILY_LIMIT} scans used today). "
                        "Google & Apple authenticated accounts are granted 3 link evaluations per day. "
                        "Access resets at 00:00 UTC, or switch to Developer Clearance for unlimited queries."
                    )
                )

        # Increment usage
        record.scan_count += 1
        db.commit()
        db.refresh(record)

        limit = None if is_developer else STANDARD_USER_DAILY_LIMIT
        remaining = 999999 if is_developer else max(0, STANDARD_USER_DAILY_LIMIT - record.scan_count)

        return {
            "user_identifier": identifier,
            "role": "developer" if is_developer else "user",
            "daily_limit": limit,
            "used_today": record.scan_count,
            "remaining": remaining,
            "unlimited": is_developer,
            "can_analyze": is_developer or (remaining > 0),
            "reset_cycle": "UNLIMITED_CLEARANCE" if is_developer else f"{today} 23:59:59 UTC"
        }


quota_service = QuotaService()
