from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List, Optional
import json

from ...core.database import get_db
from ...models.models import Asset, InventorySnapshot, User, VulnerabilityFinding, EvidenceRecord
from ...schemas.schemas import (
    AssetCreate, AssetUpdate, AssetResponse, InventorySnapshotResponse, EvidenceRecordResponse
)
from ...services.inventory_parser import InventoryParser, InventoryParseException
from ...services.audit_service import audit_service
from ..deps import get_current_user, require_admin

router = APIRouter(prefix="/assets", tags=["Asset Management"])

@router.get("", response_model=List[AssetResponse])
def list_assets(
    status: Optional[str] = None,
    environment: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Asset)
    if status:
        query = query.filter(Asset.status == status)
    if environment:
        query = query.filter(Asset.environment == environment)
    return query.order_by(Asset.created_at.desc()).all()

@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    asset_in: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    asset = Asset(**asset_in.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)

    audit_service.log_event(
        db=db,
        event_type="assessment",
        action="asset_created",
        user_id=current_user.id,
        user_email=current_user.email,
        details={"asset_id": asset.id, "name": asset.name, "os_type": asset.os_type}
    )
    return asset

@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset

@router.put("/{asset_id}", response_model=AssetResponse)
@router.patch("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: str,
    asset_in: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    update_data = asset_in.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(asset, field, val)

    db.commit()
    db.refresh(asset)
    return asset

@router.delete("/{asset_id}")
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    asset_name = asset.name
    db.delete(asset)
    db.commit()

    audit_service.log_event(
        db=db,
        event_type="assessment",
        action="asset_deleted",
        user_id=current_user.id,
        user_email=current_user.email,
        details={"asset_id": asset_id, "name": asset_name}
    )
    return {"message": "Asset deleted successfully"}

@router.post("/{asset_id}/inventory", response_model=InventorySnapshotResponse)
async def import_inventory(
    asset_id: str,
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    format_type: Optional[str] = Form("json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    content_str = ""
    filename = "manual_import"

    if file:
        filename = file.filename or "uploaded_inventory"
        bytes_data = await file.read()
        # Enforce file size limit (max 10MB)
        if len(bytes_data) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Inventory file exceeds 10MB maximum limit")
        try:
            content_str = bytes_data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Inventory file must be valid UTF-8 text")
    elif raw_content:
        content_str = raw_content
    else:
        raise HTTPException(status_code=400, detail="Either a file upload or raw_content must be provided")

    # Detect format from extension or parameter
    fmt = "csv" if (filename.endswith(".csv") or format_type == "csv") else "json"

    try:
        if fmt == "csv":
            packages, config_meta = InventoryParser.parse_csv(content_str)
        else:
            packages, config_meta = InventoryParser.parse_json(content_str)
    except InventoryParseException as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Comprehensive Phase 2 Inventory Validation
    validation_report = InventoryParser.validate_inventory(packages, config_meta)
    if not validation_report["is_valid"]:
        raise HTTPException(
            status_code=400,
            detail=f"Inventory validation failed: {'; '.join(validation_report['errors'])}"
        )

    # Attach validation summary for audit trail
    config_meta["_validation_summary"] = validation_report

    snapshot = InventorySnapshot(
        asset_id=asset.id,
        format=fmt,
        raw_filename=filename,
        packages_count=len(packages),
        parsed_packages=packages,
        configuration_metadata=config_meta
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)

    audit_service.log_event(
        db=db,
        event_type="assessment",
        action="inventory_imported",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "asset_id": asset.id,
            "packages_count": len(packages),
            "format": fmt,
            "duplicates_detected": validation_report["duplicate_count"]
        }
    )

    return snapshot

@router.post("/{asset_id}/inventory/validate")
async def validate_inventory_payload(
    asset_id: str,
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    format_type: Optional[str] = Form("json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Validate JSON or CSV inventory without saving to database."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    content_str = ""
    filename = "validation_check"

    if file:
        filename = file.filename or "validation_file"
        bytes_data = await file.read()
        if len(bytes_data) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Inventory file exceeds 10MB maximum limit")
        try:
            content_str = bytes_data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Inventory file must be valid UTF-8 text")
    elif raw_content:
        content_str = raw_content
    else:
        raise HTTPException(status_code=400, detail="Either a file upload or raw_content must be provided")

    fmt = "csv" if (filename.endswith(".csv") or format_type == "csv") else "json"

    try:
        if fmt == "csv":
            packages, config_meta = InventoryParser.parse_csv(content_str)
        else:
            packages, config_meta = InventoryParser.parse_json(content_str)
    except InventoryParseException as e:
        return {
            "is_valid": False,
            "total_packages": 0,
            "valid_packages_count": 0,
            "invalid_packages_count": 0,
            "errors": [str(e)],
            "warnings": [],
            "format": fmt
        }

    report = InventoryParser.validate_inventory(packages, config_meta)
    report["format"] = fmt
    return report

@router.get("/{asset_id}/snapshots", response_model=List[InventorySnapshotResponse])
def get_asset_snapshots(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(InventorySnapshot).filter(InventorySnapshot.asset_id == asset_id).order_by(InventorySnapshot.created_at.desc()).all()

@router.get("/{asset_id}/evidence", response_model=List[EvidenceRecordResponse])
def get_asset_evidence(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all evidence records linked to vulnerability findings on this asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return (
        db.query(EvidenceRecord)
        .join(VulnerabilityFinding, EvidenceRecord.finding_id == VulnerabilityFinding.id)
        .filter(VulnerabilityFinding.asset_id == asset_id)
        .order_by(EvidenceRecord.collected_at.desc())
        .all()
    )
