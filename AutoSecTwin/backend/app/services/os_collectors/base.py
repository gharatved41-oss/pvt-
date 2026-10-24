"""Pluggable abstract interface for operating system security evidence collectors."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.schemas.os_evidence import OSEvidenceItemCreate, OSEvidenceStatus, OSPermissionState
from app.utils.os_detect import detect_os_family


class BaseOSCollector(ABC):
    """Abstract base class for all operating system security evidence collectors.

    All subclasses must perform strictly read-only inspections.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Standardized unique collector identifier."""
        pass

    @property
    @abstractmethod
    def check_id(self) -> str:
        """Standardized check classification identifier."""
        pass

    @property
    def description(self) -> str:
        """Human-readable collector description."""
        return "Operating system read-only security evidence collector"

    @property
    def supported_os_families(self) -> List[str]:
        """List of supported operating system families (e.g. ['linux'], ['windows'])."""
        return ["linux", "windows"]

    def is_supported(self, os_family: Optional[str] = None) -> bool:
        """Determine whether this collector supports the given or current OS family."""
        target_family = os_family or detect_os_family()
        return target_family.lower() in [f.lower() for f in self.supported_os_families]

    @abstractmethod
    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Execute read-only evidence collection.

        Args:
            context: Optional execution parameters, paths, or injected test readers.

        Returns:
            List of OSEvidenceItemCreate observation instances.
        """
        pass
