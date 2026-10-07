"""Digital Twin REST API Endpoints.
Safe verification, remediation application, and before/after security regression testing.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional

from backend.app.services.digital_twin_engine import digital_twin_engine
from backend.app.core.logging import logger

router = APIRouter()

# In-memory twin session store for fast 3-hour demo execution
_ACTIVE_TWINS: Dict[str, Any] = {}


class CreateTwinRequest(BaseModel):
    target: str
    risk_score: int
    verdict: str
    indicators: Optional[Dict[str, Any]] = None


class RemediateTwinRequest(BaseModel):
    twin_id: str


@router.post("/twin/create")
def create_twin_endpoint(payload: CreateTwinRequest):
    """Generates a controlled Digital Twin simulation for safe verification."""
    twin_data = digital_twin_engine.create_twin_model(
        target=payload.target,
        risk_score=payload.risk_score,
        verdict=payload.verdict,
        parsed_indicators=payload.indicators or {}
    )
    _ACTIVE_TWINS[twin_data["twin_id"]] = twin_data
    return twin_data


@router.get("/twin/{twin_id}")
def get_twin_endpoint(twin_id: str):
    """Retrieves current state of a Digital Twin."""
    twin = _ACTIVE_TWINS.get(twin_id)
    if not twin:
        raise HTTPException(status_code=404, detail="Digital Twin not found.")
    return twin


@router.post("/twin/remediate")
def remediate_twin_endpoint(payload: RemediateTwinRequest):
    """Applies remediation to the Digital Twin, runs re-test, and returns BEFORE vs AFTER delta."""
    twin = _ACTIVE_TWINS.get(payload.twin_id)
    if not twin:
        # Generate default twin if not found
        twin = digital_twin_engine.create_twin_model("example.com", 78, "MALICIOUS", {})
        _ACTIVE_TWINS[payload.twin_id] = twin

    updated_twin = digital_twin_engine.remediate_and_retest(twin)
    _ACTIVE_TWINS[payload.twin_id] = updated_twin
    return updated_twin
