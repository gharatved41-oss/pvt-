"""Pluggable collector interface and management for security evidence gathering."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.schemas.evidence import EvidenceCollectionStatus, EvidenceItemCreate

logger = logging.getLogger("vulntwin_ai.collector")


class BaseCollector(ABC):
    """Abstract base class for all security evidence collectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Standardized unique collector identifier."""
        pass

    @property
    def description(self) -> str:
        """Human-readable collector description."""
        return "Passive security evidence collector"

    @abstractmethod
    def collect(self, url: str, context: Optional[Dict[str, Any]] = None) -> List[EvidenceItemCreate]:
        """Collect security evidence observations for the given target URL.

        Args:
            url: Canonical target URL to inspect.
            context: Optional contextual parameters or pre-parsed data.

        Returns:
            List of EvidenceItemCreate observation objects.
        """
        pass


class CollectorManager:
    """Orchestrates registration and safe execution of pluggable evidence collectors."""

    def __init__(self) -> None:
        self._collectors: List[BaseCollector] = []

    def register(self, collector: BaseCollector) -> None:
        """Register a new collector instance."""
        if not isinstance(collector, BaseCollector):
            raise TypeError(f"Collector must inherit from BaseCollector, got {type(collector)}")
        self._collectors.append(collector)
        logger.info("Registered evidence collector: %s", collector.name)

    @property
    def registered_collectors(self) -> List[str]:
        """List names of currently registered collectors."""
        return [c.name for c in self._collectors]

    def run_all(
        self, url: str, context: Optional[Dict[str, Any]] = None
    ) -> List[EvidenceItemCreate]:
        """Execute all registered collectors sequentially with robust error isolation.

        If a collector raises an unexpected exception, the error is captured as an
        evidence item with collection_status='error', preventing pipeline halts.

        Args:
            url: Canonical target URL to inspect.
            context: Optional contextual parameters.

        Returns:
            Aggregated list of collected evidence records.
        """
        all_evidence: List[EvidenceItemCreate] = []

        for collector in self._collectors:
            try:
                evidence_items = collector.collect(url=url, context=context)
                all_evidence.extend(evidence_items)
            except Exception as exc:
                logger.error(
                    "Collector '%s' raised an unhandled exception for URL '%s': %s",
                    collector.name,
                    url,
                    exc,
                    exc_info=True,
                )
                # Persist the error safely as an evidence record with status ERROR
                error_item = EvidenceItemCreate(
                    signal_name=f"{collector.name}_execution_status",
                    observed_value=f"Error: {type(exc).__name__}",
                    structured_data={
                        "collector": collector.name,
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    },
                    evidence_source=collector.name,
                    collection_status=EvidenceCollectionStatus.ERROR,
                    explanatory_notes=(
                        f"Collector '{collector.name}' encountered a runtime failure: {exc}. "
                        "The analysis pipeline safely recorded the error and continued execution."
                    ),
                )
                all_evidence.append(error_item)

        return all_evidence
