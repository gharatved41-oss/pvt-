from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from ...core.database import get_db
from ...models.models import DigitalTwin, Asset, User
from ...schemas.schemas import DigitalTwinCreate, DigitalTwinResponse, TwinActionRequest
from ...services.twin_engine import twin_engine
from ...services.audit_service import audit_service
from ..deps import get_current_user

router = APIRouter(prefix="/twins", tags=["Digital Twin Management"])

@router.get("/templates")
def list_templates(current_user: User = Depends(get_current_user)):
    return twin_engine.get_templates()

@router.get("", response_model=List[DigitalTwinResponse])
def list_twins(
    asset_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(DigitalTwin)
    if asset_id:
        query = query.filter(DigitalTwin.asset_id == asset_id)
    return query.order_by(DigitalTwin.created_at.desc()).all()

@router.post("", response_model=DigitalTwinResponse, status_code=status.HTTP_201_CREATED)
def create_twin(
    twin_in: DigitalTwinCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    asset = db.query(Asset).filter(Asset.id == twin_in.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Use twin adapter to instantiate isolated replica
    twin_data = twin_engine.create_twin(
        asset_id=asset.id,
        asset_name=asset.name,
        template_name=twin_in.template_name,
        config={"os": asset.os_version, "environment": asset.environment}
    )

    twin = DigitalTwin(
        asset_id=asset.id,
        name=twin_in.name or twin_data["name"],
        provider=twin_data["provider"],
        template_name=twin_in.template_name,
        status=twin_data["status"],
        ip_address=twin_data["ip_address"],
        network_isolated=twin_data["network_isolated"],
        snapshot_status=twin_data["snapshot_status"],
        target_config=twin_data["target_config"],
        current_config=twin_data["current_config"],
        config_parity_score=twin_data["config_parity_score"]
    )
    db.add(twin)
    db.commit()
    db.refresh(twin)

    audit_service.log_event(
        db=db,
        event_type="twin",
        action="twin_created",
        user_id=current_user.id,
        user_email=current_user.email,
        details={"twin_id": twin.id, "asset_id": asset.id, "template": twin.template_name}
    )
    return twin

@router.get("/{twin_id}", response_model=DigitalTwinResponse)
def get_twin(
    twin_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    twin = db.query(DigitalTwin).filter(DigitalTwin.id == twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Digital Twin not found")
    return twin

@router.post("/{twin_id}/actions")
def execute_twin_action(
    twin_id: str,
    action_req: TwinActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    twin = db.query(DigitalTwin).filter(DigitalTwin.id == twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Digital Twin not found")

    action = action_req.action
    result = {}

    if action == "reset_snapshot":
        result = twin_engine.reset_to_snapshot(twin.id, "baseline")
        twin.status = "ready"
        twin.snapshot_status = "restored-to-baseline"
        twin.updated_at = datetime.now(timezone.utc)
        db.commit()
    elif action == "create_snapshot":
        snap_name = f"snapshot-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        result = twin_engine.take_snapshot(twin.id, snap_name)
        twin.snapshot_status = snap_name
        db.commit()
    elif action == "verify_isolation":
        result = twin_engine.verify_isolation(twin.id)
    elif action == "stop":
        twin.status = "stopped"
        db.commit()
        result = {"status": "stopped", "message": "Digital Twin paused cleanly"}
    elif action == "start":
        twin.status = "ready"
        db.commit()
        result = {"status": "ready", "message": "Digital Twin online in isolated lab"}

    audit_service.log_event(
        db=db,
        event_type="twin",
        action=f"twin_{action}",
        user_id=current_user.id,
        user_email=current_user.email,
        details={"twin_id": twin.id, "result": result}
    )

    return {"action": action, "status": "success", "result": result}
