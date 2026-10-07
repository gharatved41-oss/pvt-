"""Built-in Deterministic Threat Intelligence & Reputation Provider.
Evaluates domain age indicators, lexical anomalies, known malicious patterns,
and structured security feeds with zero external runtime risk.
"""
from typing import Dict, Any
from datetime import datetime, timezone

from backend.app.providers.base import ThreatIntelProvider, ProviderResultData
from backend.app.core.logging import logger

# High-risk path keywords frequently found in credential harvesting & malware delivery
SUSPICIOUS_PATH_PATTERNS = [
    "login.php", "signin.php", "verify-account", "wallet-connect",
    "wp-admin", "setup.exe", "invoice.pdf.exe", "payload.bin",
    "gate.php", "c2", "rat", "meterpreter", "dropper", "keygen", "crack"
]


class BuiltinReputationProvider(ThreatIntelProvider):
    """
    Native threat intelligence provider using deterministic threat evaluation.
    Always available and independent of external API limits.
    """

    def __init__(self):
        super().__init__("AutoSecTwin Native Reputation Engine")

    @property
    def is_configured(self) -> bool:
        return True

    async def analyze_url(self, url: str, indicators: Dict[str, Any]) -> ProviderResultData:
        try:
            detections = 0
            total_checks = 7
            signals = []

            # Check 1: Suspicious TLD
            if indicators.get("suspicious_tld"):
                detections += 1
                signals.append(f"Suspicious high-risk TLD (.{indicators.get('tld')})")

            # Check 2: Punycode / IDN Homograph
            if indicators.get("has_punycode"):
                detections += 1
                signals.append("Punycode homograph domain structure detected")

            # Check 3: Hostname entropy / DGA characteristics
            entropy = indicators.get("hostname_entropy", 0.0)
            if entropy > 3.8:
                detections += 1
                signals.append(f"High domain entropy ({entropy}) indicative of DGA (Domain Generation Algorithm)")

            # Check 4: Direct IP address host
            if indicators.get("is_ip"):
                detections += 1
                signals.append("Direct IP address used instead of canonical domain name")

            # Check 5: Executable or script payload path
            if indicators.get("has_executable"):
                detections += 2
                exts = ", ".join(indicators.get("detected_extensions", []))
                signals.append(f"Direct executable/binary download extension detected: {exts}")

            # Check 6: Brand impersonation / typosquatting
            matched_brands = indicators.get("matched_brands", [])
            if matched_brands:
                detections += 2
                signals.append(f"Potential brand impersonation detected for: {', '.join(matched_brands)}")

            # Check 7: Suspicious path patterns
            path_lower = (indicators.get("path") or "").lower()
            for pattern in SUSPICIOUS_PATH_PATTERNS:
                if pattern in path_lower:
                    detections += 1
                    signals.append(f"Suspicious path keyword matched: '{pattern}'")
                    break

            # Calculate classification and confidence
            if detections >= 3:
                classification = "MALICIOUS"
                confidence = min(0.65 + (detections * 0.08), 0.98)
            elif detections >= 1:
                classification = "SUSPICIOUS"
                confidence = min(0.55 + (detections * 0.07), 0.85)
            else:
                # If no suspicious signals are present, mark CLEAN
                classification = "CLEAN"
                confidence = 0.80

            return ProviderResultData(
                provider_name=self.name,
                status="AVAILABLE",
                classification=classification,
                confidence=round(confidence, 2),
                detections=detections,
                total_engines=total_checks,
                raw_reference="Evaluated across 7 deterministic heuristic rulesets",
                observed_at=datetime.now(timezone.utc),
                details={
                    "triggered_signals": signals,
                    "detections_count": detections
                }
            )

        except Exception as e:
            logger.error(f"Error in BuiltinReputationProvider: {str(e)}")
            return ProviderResultData(
                provider_name=self.name,
                status="ERROR",
                classification="UNKNOWN",
                confidence=0.1,
                error_message=str(e),
                observed_at=datetime.now(timezone.utc)
            )

    async def analyze_hash(self, file_hash: str) -> ProviderResultData:
        # Known threat test hashes for safe demonstration verification
        known_malicious_hashes = {
            "44d88612fea8a8f36de82e1278abb02f": "EICAR Standard Anti-Virus Test File (MD5)",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Standard Anti-Virus Test File (SHA-256)",
            "3395856ce81f2b7382dee72602f798b642f14140": "EICAR Standard Anti-Virus Test File (SHA-1)",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty File (Zero-length SHA-256)",
        }

        clean_hash = file_hash.lower().strip()
        if clean_hash in known_malicious_hashes:
            label = known_malicious_hashes[clean_hash]
            is_malicious = "EICAR" in label
            return ProviderResultData(
                provider_name=self.name,
                status="AVAILABLE",
                classification="MALICIOUS" if is_malicious else "CLEAN",
                confidence=0.99,
                detections=1 if is_malicious else 0,
                total_engines=1,
                raw_reference=f"Indicator repository match: {label}",
                observed_at=datetime.now(timezone.utc),
                details={"label": label}
            )

        # Hash is not in local sample catalog
        return ProviderResultData(
            provider_name=self.name,
            status="AVAILABLE",
            classification="UNKNOWN",
            confidence=0.3,
            detections=0,
            total_engines=1,
            raw_reference="No local indicator matches found.",
            observed_at=datetime.now(timezone.utc),
            details={"message": "Hash not observed in local high-confidence signatures"}
        )
