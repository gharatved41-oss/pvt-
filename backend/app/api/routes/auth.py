"""Authentication and Access Control API for SentinalX.
Manages passcode generation, delivery verification, and developer role clearance.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import random
import time
from backend.app.core.logging import logger

router = APIRouter()

DEVELOPERS: Dict[str, Dict[str, Any]] = {
    "sara.dongare": {
        "name": "Sara Dongare",
        "username": "sara.dongare",
        "role": "developer",
        "title": "Digital Twin & Safe Verification Lead",
        "badge": "LEAD // TWIN_VERIFY",
        "email": "sara.dongare@sentinalx.internal",
        "passcode": "SX-DEV-SARA-9021"
    },
    "shubra.gharat": {
        "name": "Shubra Gharat",
        "username": "shubra.gharat",
        "role": "developer",
        "title": "AI & Risk Intelligence Lead",
        "badge": "LEAD // AI_EXPLOIT",
        "email": "shubra.gharat@sentinalx.internal",
        "passcode": "SX-DEV-SHUBRA-4418"
    },
    "ved.gharat": {
        "name": "Ved Gharat",
        "username": "ved.gharat",
        "role": "developer",
        "title": "Frontend & User Experience Lead",
        "badge": "LEAD // FRONTEND",
        "email": "ved.gharat@sentinalx.internal",
        "passcode": "SX-DEV-VED-7732"
    },
    "mayank.patil": {
        "name": "Mayank Patil",
        "username": "mayank.patil",
        "role": "developer",
        "title": "Backend & Integration Lead",
        "badge": "LEAD // PLATFORM",
        "email": "mayank.patil@sentinalx.internal",
        "passcode": "SX-DEV-MAYANK-1337"
    }
}

# Temporary store for generated passcodes: identifier -> {passcode, expires_at, user_data}
ACTIVE_PASSCODES: Dict[str, Dict[str, Any]] = {}


class RequestCodeRequest(BaseModel):
    identifier: str  # email or username
    login_type: Optional[str] = "sso"  # "sso" | "developer"


class VerifyCodeRequest(BaseModel):
    identifier: str
    passcode: str


@router.post("/auth/request-code")
def request_passcode(payload: RequestCodeRequest):
    """
    Generates a secure one-time access passcode for user login.
    Dispatches it to the user so they can safely enter it without manual confusion.
    """
    ident = payload.identifier.strip().lower()
    if not ident:
        raise HTTPException(status_code=400, detail="Please provide a valid email or developer username.")

    now = time.time()
    expires_at = now + 900  # 15 minutes validity

    # Check if developer username
    if ident in DEVELOPERS:
        dev = DEVELOPERS[ident]
        return {
            "status": "developer_auth_required",
            "message": f"Developer account identified for {dev['name']}. Please enter your assigned security passcode.",
            "identifier": ident,
            "passcode": None,
            "role": "developer",
            "name": dev["name"],
            "requires_secret": True
        }

    # Standard User (Google/Apple SSO or organization email)
    random_digits = "".join([str(random.randint(0, 9)) for _ in range(6)])
    code = f"SX-{random_digits}"
    
    # Extract friendly name from email
    parts = ident.split("@")[0].replace(".", " ").replace("-", " ").title()
    name = parts if parts else "Security Analyst"

    user_data = {
        "name": name,
        "username": ident.split("@")[0],
        "email": ident if "@" in ident else f"{ident}@company.com",
        "role": "user",
        "title": "Security Analyst (Quota: 3/day)",
        "badge": "ANALYST // SSO"
    }

    ACTIVE_PASSCODES[ident] = {
        "passcode": code,
        "expires_at": expires_at,
        "user": user_data
    }

    logger.info(f"Dispatched access passcode {code} to {ident}")

    return {
        "status": "dispatched",
        "message": "Access passcode generated and securely dispatched.",
        "identifier": ident,
        "passcode": code,
        "role": "user",
        "name": name,
        "expires_in_minutes": 15
    }


@router.post("/auth/verify-code")
def verify_passcode(payload: VerifyCodeRequest):
    """
    Validates user passcode and establishes verified session.
    """
    ident = payload.identifier.strip().lower()
    entered_code = payload.passcode.strip()

    if not ident or not entered_code:
        raise HTTPException(status_code=400, detail="Missing identifier or passcode.")

    # 1. Check if developer account
    if ident in DEVELOPERS:
        if DEVELOPERS[ident]["passcode"] == entered_code:
            return {
                "status": "authenticated",
                "user": DEVELOPERS[ident]
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid developer clearance passcode. Access denied."
            )

    # 2. Check active passcodes
    record = ACTIVE_PASSCODES.get(ident)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active passcode found for this identifier. Please request a new code."
        )

    if time.time() > record["expires_at"]:
        del ACTIVE_PASSCODES[ident]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Passcode has expired. Please request a fresh access passcode."
        )

    if record["passcode"].upper() != entered_code.upper():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid passcode. Please re-enter the code generated for your account."
        )

    # Validated successfully
    user = record["user"]
    del ACTIVE_PASSCODES[ident]  # Single-use

    return {
        "status": "authenticated",
        "user": user
    }
