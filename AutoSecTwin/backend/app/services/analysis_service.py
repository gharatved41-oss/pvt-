"""Database service operations and orchestration for target analysis and evidence records."""

import logging
from typing import List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.analysis import AnalysisRecord, AnalysisStatus
from app.models.evidence import SecurityEvidenceRecord
from app.schemas.evidence import EvidenceItemCreate
from app.schemas.risk import RiskAssessmentResponse
from app.services.collector import CollectorManager
from app.services.passive_analyzer import PassiveUrlAnalyzer
from app.services.risk_engine import DeterministicPassiveRiskEngine

logger = logging.getLogger("vulntwin_ai.analysis_service")


class InvalidStatusTransitionError(Exception):
    """Raised when an illegal lifecycle status transition is requested."""

    pass


def create_analysis(db: Session, url: str) -> AnalysisRecord:
    """Create and persist a new target analysis record with 'pending' status.

    Args:
        db: Active database session.
        url: Validated canonical target URL.

    Returns:
        Persisted AnalysisRecord instance.
    """
    record = AnalysisRecord(url=url, status=AnalysisStatus.PENDING.value)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_analysis_by_id(db: Session, analysis_id: str) -> Optional[AnalysisRecord]:
    """Retrieve an analysis record by its primary UUID.

    Args:
        db: Active database session.
        analysis_id: UUID string of the record.

    Returns:
        AnalysisRecord if found, None otherwise.
    """
    statement = select(AnalysisRecord).where(AnalysisRecord.id == analysis_id)
    return db.scalars(statement).first()


def list_analyses(
    db: Session, limit: int = 20, offset: int = 0
) -> Tuple[List[AnalysisRecord], int]:
    """Retrieve a paginated list of analysis records along with total count.

    Args:
        db: Active database session.
        limit: Maximum number of records to return.
        offset: Number of records to skip.

    Returns:
        Tuple containing (list of records, total count).
    """
    total = db.scalar(select(func.count(AnalysisRecord.id))) or 0

    statement = (
        select(AnalysisRecord)
        .order_by(AnalysisRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    records = list(db.scalars(statement).all())
    return records, total


def transition_status(
    db: Session,
    record: AnalysisRecord,
    new_status: str,
    error_message: Optional[str] = None,
) -> AnalysisRecord:
    """Validate and persist a state machine transition on an AnalysisRecord.

    Args:
        db: Active database session.
        record: AnalysisRecord instance to update.
        new_status: Target status string (from AnalysisStatus).
        error_message: Optional diagnostic error message.

    Returns:
        Updated AnalysisRecord.

    Raises:
        InvalidStatusTransitionError: If the transition is prohibited by state machine rules.
    """
    if not record.can_transition_to(new_status):
        raise InvalidStatusTransitionError(
            f"Cannot transition analysis '{record.id}' from status '{record.status}' to '{new_status}'."
        )

    record.status = new_status
    if error_message is not None:
        record.error_message = error_message
    elif new_status == AnalysisStatus.COMPLETED.value:
        record.error_message = None

    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def add_evidence_items(
    db: Session,
    analysis_id: str,
    evidence_items: List[EvidenceItemCreate],
) -> List[SecurityEvidenceRecord]:
    """Persist multiple evidence records associated with an analysis ID.

    Args:
        db: Active database session.
        analysis_id: Parent analysis UUID.
        evidence_items: List of observation schemas to persist.

    Returns:
        List of created and refreshed SecurityEvidenceRecord entities.
    """
    records: List[SecurityEvidenceRecord] = []
    for item in evidence_items:
        rec = SecurityEvidenceRecord(
            analysis_id=analysis_id,
            signal_name=item.signal_name,
            observed_value=item.observed_value,
            structured_data=item.structured_data,
            evidence_source=item.evidence_source,
            collection_status=item.collection_status.value if hasattr(item.collection_status, "value") else str(item.collection_status),
            explanatory_notes=item.explanatory_notes,
        )
        db.add(rec)
        records.append(rec)

    db.commit()
    for rec in records:
        db.refresh(rec)
    return records


def get_evidence_by_analysis_id(
    db: Session, analysis_id: str
) -> List[SecurityEvidenceRecord]:
    """Retrieve all security evidence items for a given analysis record.

    Args:
        db: Active database session.
        analysis_id: Parent analysis UUID.

    Returns:
        List of SecurityEvidenceRecord entities ordered by observation timestamp.
    """
    statement = (
        select(SecurityEvidenceRecord)
        .where(SecurityEvidenceRecord.analysis_id == analysis_id)
        .order_by(SecurityEvidenceRecord.observation_timestamp.asc())
    )
    return list(db.scalars(statement).all())


def run_passive_analysis(
    db: Session,
    record: AnalysisRecord,
    collector_manager: Optional[CollectorManager] = None,
    risk_engine: Optional[DeterministicPassiveRiskEngine] = None,
) -> Tuple[AnalysisRecord, List[SecurityEvidenceRecord], RiskAssessmentResponse]:
    """Execute end-to-end passive security evidence collection and risk scoring.

    Workflow:
      1. Validates and transitions record from 'pending' to 'running'.
      2. Executes passive collectors (safe local syntax and hostname analysis).
      3. Persists gathered evidence records linked to analysis_id.
      4. Calculates deterministic risk assessment with confidence & exploitability.
      5. Transitions record from 'running' to 'completed' (or 'failed' on system crash).

    Args:
        db: Active database session.
        record: Target AnalysisRecord to analyze.
        collector_manager: Optional custom CollectorManager.
        risk_engine: Optional custom DeterministicPassiveRiskEngine.

    Returns:
        Tuple of (updated AnalysisRecord, list of SecurityEvidenceRecord, RiskAssessmentResponse).
    """
    # Initialize default components if not provided
    if collector_manager is None:
        collector_manager = CollectorManager()
        collector_manager.register(PassiveUrlAnalyzer())

    if risk_engine is None:
        risk_engine = DeterministicPassiveRiskEngine()

    # Step 1: Transition pending -> running
    transition_status(db, record, AnalysisStatus.RUNNING.value)

    try:
        # Step 2: Run collectors safely
        evidence_items = collector_manager.run_all(url=record.url)

        # Step 3: Persist evidence items to database
        persisted_evidence = add_evidence_items(db, record.id, evidence_items)

        # Step 4: Evaluate deterministic risk
        risk_assessment = risk_engine.evaluate(persisted_evidence)

        # Step 5: Transition running -> completed
        transition_status(db, record, AnalysisStatus.COMPLETED.value)

        return record, persisted_evidence, risk_assessment

    except Exception as exc:
        logger.error(
            "Fatal failure during analysis execution for '%s': %s",
            record.id,
            exc,
            exc_info=True,
        )
        transition_status(
            db,
            record,
            AnalysisStatus.FAILED.value,
            error_message=f"Analysis pipeline error: {type(exc).__name__}: {exc}",
        )
        raise
