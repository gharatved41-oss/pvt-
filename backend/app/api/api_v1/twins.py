from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from ...core.database import get_db
from ...models.models import DigitalTwin, Asset, InventorySnapshot, User
from ...schemas.schemas import (
    DigitalTwinCreate, DigitalTwinResponse, TwinActionRequest, ConfigComparisonResponse
)
from ...services.twin_engine import twin_engine, provider_registry
from ...services.audit_service import audit_service
from ..deps import get_current_user, require_admin

router = APIRouter(prefix="/twins", tags=["Digital Twin Management"])

@router.get("/templates")
def list_templates(current_user: User = Depends(get_current_user)):
    """List available pre-configured environment templates with simulation labels."""
    return twin_engine.get_templates()

@router.get("/providers")
def list_providers(current_user: User = Depends(get_current_user)):
    """List supported virtualization and simulation provider adapters."""
    return {
        "active_provider": twin_engine.provider_name,
        "is_simulation": twin_engine.is_simulation(),
        "available_providers": provider_registry.list_providers()
    }

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

    # Get target config from latest asset inventory snapshot or asset properties
    target_config = {
        "os": asset.os_version,
        "os_type": asset.os_type,
        "environment": asset.environment,
        "criticality": asset.criticality
    }
    latest_snapshot = db.query(InventorySnapshot).filter(
        InventorySnapshot.asset_id == asset.id
    ).order_by(InventorySnapshot.created_at.desc()).first()

    if latest_snapshot and latest_snapshot.configuration_metadata:
        # Merge configuration metadata
        target_config.update(latest_snapshot.configuration_metadata)

    # Resolve virtualization/simulation provider
    provider_name = twin_in.provider or "mock_isolated"
    adapter = provider_registry.get_provider(provider_name)

    twin_data = adapter.create_twin(
        asset_id=asset.id,
        asset_name=asset.name,
        template_name=twin_in.template_name,
        target_config=target_config
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
        details={
            "twin_id": twin.id,
            "asset_id": asset.id,
            "template": twin.template_name,
            "provider": twin.provider,
            "is_simulation": True
        }
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

@router.delete("/{twin_id}")
def delete_twin(
    twin_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete a digital twin record and release lab resources (admin only)."""
    twin = db.query(DigitalTwin).filter(DigitalTwin.id == twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Digital Twin not found")

    name = twin.name
    asset_id = twin.asset_id
    db.delete(twin)
    db.commit()

    audit_service.log_event(
        db=db,
        event_type="twin",
        action="twin_deleted",
        user_id=current_user.id,
        user_email=current_user.email,
        details={"twin_id": twin_id, "name": name, "asset_id": asset_id}
    )
    return {"message": f"Digital Twin '{name}' decommissioned successfully"}

@router.get("/{twin_id}/compare-config", response_model=ConfigComparisonResponse)
def compare_twin_configuration(
    twin_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Compare target production asset configuration against digital twin replica."""
    twin = db.query(DigitalTwin).filter(DigitalTwin.id == twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Digital Twin not found")

    report = twin_engine.compare_config(twin.target_config or {}, twin.current_config or {})

    # Update parity score in twin record
    twin.config_parity_score = report["config_parity_score"]
    db.commit()

    return {
        "twin_id": twin.id,
        "asset_id": twin.asset_id,
        "config_parity_score": report["config_parity_score"],
        "matched_parameters": report["matched_parameters"],
        "differing_parameters": report["differing_parameters"],
        "missing_in_twin": report["missing_in_twin"],
        "missing_in_target": report["missing_in_target"],
        "summary": report["summary"]
    }

@router.get("/{twin_id}/isolation")
def get_twin_isolation_telemetry(
    twin_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Query isolation verification diagnostics for airgap compliance."""
    twin = db.query(DigitalTwin).filter(DigitalTwin.id == twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Digital Twin not found")

    telemetry = twin_engine.verify_isolation(twin.id)
    telemetry["network_isolated"] = twin.network_isolated
    telemetry["current_status"] = twin.status
    return telemetry

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
        snap = action_req.snapshot_name or "baseline"
        result = twin_engine.reset_to_snapshot(twin.id, snap)
        twin.status = "ready"
        twin.snapshot_status = f"restored-to-{snap}"
        twin.updated_at = datetime.now(timezone.utc)
        # Restore current config to target baseline config
        twin.current_config = dict(twin.target_config or {})
        twin.current_config["twin_replica"] = True
        report = twin_engine.compare_config(twin.target_config or {}, twin.current_config or {})
        twin.config_parity_score = report["config_parity_score"]
        db.commit()

    elif action in ["create_snapshot", "take_snapshot"]:
        snap_name = action_req.snapshot_name or f"snapshot-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        result = twin_engine.take_snapshot(twin.id, snap_name)
        twin.snapshot_status = snap_name
        twin.updated_at = datetime.now(timezone.utc)
        db.commit()

    elif action == "verify_isolation":
        result = twin_engine.verify_isolation(twin.id)
        twin.network_isolated = result.get("isolated", True)
        twin.updated_at = datetime.now(timezone.utc)
        db.commit()

    elif action == "stop":
        if twin.status == "testing":
            raise HTTPException(status_code=400, detail="Cannot stop Digital Twin while validation test is active.")
        twin.status = "stopped"
        twin.updated_at = datetime.now(timezone.utc)
        db.commit()
        result = {"status": "stopped", "message": "Digital Twin paused cleanly; resources suspended."}

    elif action == "start":
        twin.status = "ready"
        twin.updated_at = datetime.now(timezone.utc)
        db.commit()
        result = {"status": "ready", "message": "Digital Twin online in isolated sandbox lab."}

    elif action == "sync_config":
        # Pull latest asset configuration snapshot
        asset = db.query(Asset).filter(Asset.id == twin.asset_id).first()
        latest_snap = db.query(InventorySnapshot).filter(
            InventorySnapshot.asset_id == twin.asset_id
        ).order_by(InventorySnapshot.created_at.desc()).first()

        new_target = dict(twin.target_config or {})
        if latest_snap and latest_snap.configuration_metadata:
            new_target.update(latest_snap.configuration_metadata)
        twin.target_config = new_target
        report = twin_engine.compare_config(twin.target_config or {}, twin.current_config or {})
        twin.config_parity_score = report["config_parity_score"]
        twin.updated_at = datetime.now(timezone.utc)
        db.commit()
        result = {
            "status": "config_synced",
            "parity_score": twin.config_parity_score,
            "summary": report["summary"]
        }

    audit_service.log_event(
        db=db,
        event_type="twin",
        action=f"twin_{action}",
        user_id=current_user.id,
        user_email=current_user.email,
        details={"twin_id": twin.id, "result": result}
    )

    return {"action": action, "status": "success", "result": result}
