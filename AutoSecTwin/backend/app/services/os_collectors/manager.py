"""Orchestrator for registering and safely executing OS evidence collectors with error containment."""

import logging
from typing import Any, Dict, List, Optional

from app.schemas.os_evidence import OSEvidenceItemCreate, OSEvidenceStatus, OSPermissionState
from app.services.os_collectors.base import BaseOSCollector
from app.utils.os_detect import detect_os_family

logger = logging.getLogger("vulntwin_ai.os_collector_manager")


class OSCollectorManager:
    """Manages the registration and safe, isolated execution of OS evidence collectors."""

    def __init__(self) -> None:
        self._collectors: List[BaseOSCollector] = []

    def register(self, collector: BaseOSCollector) -> None:
        """Register a new OS collector instance."""
        if not isinstance(collector, BaseOSCollector):
            raise TypeError(f"Collector must inherit from BaseOSCollector, got {type(collector)}")
        self._collectors.append(collector)
        logger.info("Registered OS evidence collector: %s (%s)", collector.name, collector.check_id)

    @property
    def registered_collectors(self) -> List[str]:
        """List names of currently registered collectors."""
        return [c.name for c in self._collectors]

    def run_all(
        self,
        os_family: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[OSEvidenceItemCreate]:
        """Execute all registered collectors with strict error and permission isolation.

        Collectors unsupported on the target OS family emit a 'not_checked' status.
        Permission errors emit an 'unavailable' status with 'denied' permission state.
        Runtime crashes are safely captured as 'error' items without halting the scan.

        Args:
            os_family: Target OS family ('linux', 'windows'). If None, automatically detected.
            context: Optional execution parameters or mocked dependencies.

        Returns:
            Aggregated list of collected evidence records.
        """
        target_os = (os_family or detect_os_family()).lower()
        all_evidence: List[OSEvidenceItemCreate] = []

        for collector in self._collectors:
            # Check platform compatibility
            if not collector.is_supported(target_os):
                logger.debug(
                    "Skipping collector '%s': unsupported on OS family '%s'",
                    collector.name,
                    target_os,
                )
                all_evidence.append(
                    OSEvidenceItemCreate(
                        collector_name=collector.name,
                        check_id=collector.check_id,
                        signal_name=f"{collector.name}_platform_status",
                        observed_value=f"Unsupported on {target_os}",
                        structured_data={
                            "collector": collector.name,
                            "target_os": target_os,
                            "supported_os": collector.supported_os_families,
                        },
                        collection_status=OSEvidenceStatus.NOT_CHECKED,
                        permission_state=OSPermissionState.GRANTED,
                        explanatory_notes=(
                            f"Collector '{collector.name}' does not target operating system family '{target_os}'. "
                            "Check was safely skipped without impacting other probes."
                        ),
                    )
                )
                continue

            # Execute with comprehensive error containment
            try:
                items = collector.collect(context=context)
                all_evidence.extend(items)
            except PermissionError as exc:
                logger.warning(
                    "Collector '%s' encountered PermissionError: %s",
                    collector.name,
                    exc,
                )
                all_evidence.append(
                    OSEvidenceItemCreate(
                        collector_name=collector.name,
                        check_id=collector.check_id,
                        signal_name=f"{collector.name}_access_status",
                        observed_value=f"Permission Denied: {exc}",
                        structured_data={
                            "collector": collector.name,
                            "error_type": "PermissionError",
                            "error_details": str(exc),
                        },
                        collection_status=OSEvidenceStatus.UNAVAILABLE,
                        permission_state=OSPermissionState.DENIED,
                        explanatory_notes=(
                            f"Collector '{collector.name}' could not access system metadata due to insufficient privileges ({exc}). "
                            "Audit limitation recorded. Lack of access is explicitly NOT treated as proof of safety."
                        ),
                    )
                )
            except FileNotFoundError as exc:
                logger.info(
                    "Collector '%s' target file not found: %s",
                    collector.name,
                    exc,
                )
                all_evidence.append(
                    OSEvidenceItemCreate(
                        collector_name=collector.name,
                        check_id=collector.check_id,
                        signal_name=f"{collector.name}_file_status",
                        observed_value=f"File Not Found: {exc}",
                        structured_data={
                            "collector": collector.name,
                            "error_type": "FileNotFoundError",
                            "file_missing": str(exc),
                        },
                        collection_status=OSEvidenceStatus.ABSENT,
                        permission_state=OSPermissionState.GRANTED,
                        explanatory_notes=(
                            f"Target metadata source for collector '{collector.name}' was not present on this host ({exc}). "
                            "Status recorded as ABSENT."
                        ),
                    )
                )
            except Exception as exc:
                logger.error(
                    "Collector '%s' raised an unexpected exception: %s",
                    collector.name,
                    exc,
                    exc_info=True,
                )
                all_evidence.append(
                    OSEvidenceItemCreate(
                        collector_name=collector.name,
                        check_id=collector.check_id,
                        signal_name=f"{collector.name}_execution_error",
                        observed_value=f"Error: {type(exc).__name__}",
                        structured_data={
                            "collector": collector.name,
                            "error_type": type(exc).__name__,
                            "error_message": str(exc),
                        },
                        collection_status=OSEvidenceStatus.ERROR,
                        permission_state=OSPermissionState.GRANTED,
                        explanatory_notes=(
                            f"Collector '{collector.name}' encountered a runtime failure: {exc}. "
                            "The assessment safely contained the failure and continued execution."
                        ),
                    )
                )

        return all_evidence
