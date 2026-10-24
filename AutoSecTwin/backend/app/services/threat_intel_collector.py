"""Collector adapter integrating modular threat intelligence providers into the evidence pipeline."""

import logging
from typing import Any, Dict, List, Optional

from app.providers.base import (
    BaseThreatIntelProvider,
    ThreatIntelAuthError,
    ThreatIntelError,
    ThreatIntelInvalidResponseError,
    ThreatIntelRateLimitError,
    ThreatIntelTimeoutError,
    ThreatIntelUnavailableError,
)
from app.providers.mock_provider import MockThreatIntelProvider
from app.providers.virustotal_provider import sanitize_indicator_for_logging
from app.schemas.evidence import EvidenceCollectionStatus, EvidenceItemCreate
from app.schemas.threat_intel import ThreatIntelLookupStatus, ThreatIntelResult
from app.services.collector import BaseCollector

logger = logging.getLogger("vulntwin_ai.services.threat_intel_collector")


class ThreatIntelCollector(BaseCollector):
    """Adapter collector that queries a threat intelligence provider and emits evidence records."""

    def __init__(self, provider: Optional[BaseThreatIntelProvider] = None) -> None:
        self._provider = provider or MockThreatIntelProvider()

    @property
    def name(self) -> str:
        return f"{self._provider.name}_collector"

    @property
    def description(self) -> str:
        return f"Reputation telemetry collector using provider '{self._provider.name}'"

    @property
    def provider(self) -> BaseThreatIntelProvider:
        return self._provider

    def collect(self, url: str, context: Optional[Dict[str, Any]] = None) -> List[EvidenceItemCreate]:
        """Perform threat intelligence lookup on URL and convert into standardized evidence item.

        Args:
            url: Canonical submitted URL.
            context: Optional context dictionary.

        Returns:
            List containing the formatted EvidenceItemCreate record.
        """
        signal_name = f"{self._provider.name}_reputation"

        try:
            result = self._provider.lookup(indicator=url, indicator_type="url", context=context)

            # 1. Match Outcome (Malicious, Suspicious, or other threat tags)
            if result.lookup_status == ThreatIntelLookupStatus.MATCH:
                return [
                    EvidenceItemCreate(
                        signal_name=signal_name,
                        observed_value=result.threat_verdict or "match_found",
                        structured_data={
                            "provider": result.provider_name,
                            "lookup_status": result.lookup_status.value,
                            "threat_verdict": result.threat_verdict,
                            "threat_score": result.threat_score,
                            "categories": result.categories,
                            "raw_metadata": result.raw_data,
                            "limitations": result.limitations,
                        },
                        evidence_source=result.provider_name,
                        collection_status=EvidenceCollectionStatus.OBSERVED,
                        explanatory_notes=(
                            f"Threat intelligence provider '{result.provider_name}' returned a confirmed match: "
                            f"verdict='{result.threat_verdict}' (score: {result.threat_score}/100, "
                            f"categories: {', '.join(result.categories) if result.categories else 'none'})."
                        ),
                    )
                ]

            # 2. Privacy-Blocked Outcome (Local guardrails prevented external request)
            if result.lookup_status == ThreatIntelLookupStatus.PRIVACY_BLOCKED:
                return [
                    EvidenceItemCreate(
                        signal_name=signal_name,
                        observed_value="privacy_blocked",
                        structured_data={
                            "provider": result.provider_name,
                            "lookup_status": result.lookup_status.value,
                            "threat_verdict": None,
                            "threat_score": 0,
                            "categories": [],
                            "raw_metadata": result.raw_data,
                            "limitations": result.limitations,
                        },
                        evidence_source=result.provider_name,
                        collection_status=EvidenceCollectionStatus.SKIPPED,
                        explanatory_notes=(
                            f"External threat intelligence lookup via '{result.provider_name}' was blocked by local privacy guardrails. "
                            "No data was transmitted to external third-party services. "
                            "Critical safety rule: A privacy-blocked lookup is NOT a confirmed clean or safe result."
                        ),
                    )
                ]

            # 3. Unknown Indicator Outcome (e.g., HTTP 404 - not in provider database)
            if result.lookup_status == ThreatIntelLookupStatus.UNKNOWN_INDICATOR:
                return [
                    EvidenceItemCreate(
                        signal_name=signal_name,
                        observed_value="unknown_indicator",
                        structured_data={
                            "provider": result.provider_name,
                            "lookup_status": result.lookup_status.value,
                            "threat_verdict": None,
                            "threat_score": 0,
                            "categories": [],
                            "raw_metadata": result.raw_data,
                            "limitations": result.limitations,
                        },
                        evidence_source=result.provider_name,
                        collection_status=EvidenceCollectionStatus.ABSENT,
                        explanatory_notes=(
                            f"Target indicator was not found in '{result.provider_name}' database (has never been submitted or recorded). "
                            "Critical safety rule: An unknown or unrecorded indicator is NOT evidence that the target is safe or benign."
                        ),
                    )
                ]

            # 4. Genuine Negative Finding (No Match - Scanned with 0 threat detections)
            total_engines = 0
            if result.raw_data and isinstance(result.raw_data, dict):
                total_engines = result.raw_data.get("total_engines", 0)

            engines_note = f" across {total_engines} security scanner engines" if total_engines else ""
            return [
                EvidenceItemCreate(
                    signal_name=signal_name,
                    observed_value="no_match",
                    structured_data={
                        "provider": result.provider_name,
                        "lookup_status": result.lookup_status.value,
                        "threat_verdict": None,
                        "threat_score": 0,
                        "categories": [],
                        "raw_metadata": result.raw_data,
                        "limitations": result.limitations,
                    },
                    evidence_source=result.provider_name,
                    collection_status=EvidenceCollectionStatus.ABSENT,
                    explanatory_notes=(
                        f"No reputation threat entries found{engines_note} in '{result.provider_name}' threat database. "
                        "Critical safety rule: The absence of a reported threat match does NOT certify the target is safe or benign."
                    ),
                )
            ]

        except ThreatIntelTimeoutError as exc:
            logger.warning("Threat intel lookup timed out for '%s': %s", sanitize_indicator_for_logging(url), exc)
            return [self._create_error_evidence(signal_name, "timeout", exc)]

        except ThreatIntelRateLimitError as exc:
            logger.warning("Threat intel rate limit exceeded for '%s': %s", sanitize_indicator_for_logging(url), exc)
            return [self._create_error_evidence(signal_name, "rate_limited", exc)]

        except ThreatIntelAuthError as exc:
            logger.warning("Threat intel authentication failed for '%s': %s", sanitize_indicator_for_logging(url), exc)
            return [self._create_error_evidence(signal_name, "auth_error", exc)]

        except ThreatIntelInvalidResponseError as exc:
            logger.warning("Threat intel invalid response for '%s': %s", sanitize_indicator_for_logging(url), exc)
            return [self._create_error_evidence(signal_name, "invalid_response", exc)]

        except ThreatIntelUnavailableError as exc:
            logger.warning("Threat intel provider unavailable for '%s': %s", sanitize_indicator_for_logging(url), exc)
            return [self._create_error_evidence(signal_name, "unavailable", exc)]

        except ThreatIntelError as exc:
            logger.error("Threat intel provider error for '%s': %s", sanitize_indicator_for_logging(url), exc)
            return [self._create_error_evidence(signal_name, "error", exc)]

        except Exception as exc:
            logger.error("Unexpected error in threat intel collector for '%s': %s", sanitize_indicator_for_logging(url), exc, exc_info=True)
            return [self._create_error_evidence(signal_name, "unexpected_error", exc)]

    def _create_error_evidence(
        self, signal_name: str, error_type: str, exc: Exception
    ) -> EvidenceItemCreate:
        """Create a standardized EvidenceItemCreate representing an error outcome."""
        return EvidenceItemCreate(
            signal_name=signal_name,
            observed_value=f"error_{error_type}",
            structured_data={
                "provider": self._provider.name,
                "lookup_status": error_type,
                "error_class": type(exc).__name__,
                "error_message": str(exc),
            },
            evidence_source=self._provider.name,
            collection_status=EvidenceCollectionStatus.ERROR,
            explanatory_notes=(
                f"Threat intelligence lookup via '{self._provider.name}' failed or was inconclusive ({error_type}): {exc}. "
                "Analysis safely continued without blocking pipeline execution."
            ),
        )
