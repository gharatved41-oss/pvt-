"""Modular passive URL and hostname syntax analyzer.

Performs deterministic local syntactic inspection of target URLs and hostnames
without executing any outbound network requests or invasive probes.
Observations are recorded as factual evidence signals, distinct from security conclusions.
"""

import ipaddress
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.schemas.evidence import EvidenceCollectionStatus, EvidenceItemCreate
from app.services.collector import BaseCollector

# Standard web ports
STANDARD_PORTS = {80, 443}

# Lexical keywords commonly seen in target paths/queries (for neutral observation)
SENSITIVE_KEYWORDS = {
    "login",
    "admin",
    "password",
    "passwd",
    "credential",
    "token",
    "auth",
    "verify",
    "verification",
    "update",
    "billing",
    "secure",
    "account",
}


class PassiveUrlAnalyzer(BaseCollector):
    """Local, non-intrusive syntax and hostname characteristics collector."""

    @property
    def name(self) -> str:
        return "passive_syntax_analyzer"

    @property
    def description(self) -> str:
        return "Inspects URL syntax, hostname characteristics, and structural metrics without network requests."

    def collect(self, url: str, context: Optional[Dict[str, Any]] = None) -> List[EvidenceItemCreate]:
        """Perform passive lexical and structural inspection on target URL.

        Args:
            url: Canonical target URL string.
            context: Optional execution context.

        Returns:
            List of EvidenceItemCreate observation objects.
        """
        evidence: List[EvidenceItemCreate] = []
        parsed = urlparse(url)

        # -------------------------------------------------------------
        # 1. URL Scheme Observation
        # -------------------------------------------------------------
        scheme = parsed.scheme.lower()
        is_encrypted = scheme == "https"
        evidence.append(
            EvidenceItemCreate(
                signal_name="url_scheme",
                observed_value=scheme,
                structured_data={
                    "scheme": scheme,
                    "is_tls_encrypted": is_encrypted,
                },
                evidence_source=self.name,
                collection_status=EvidenceCollectionStatus.OBSERVED,
                explanatory_notes=(
                    "Target URL specifies HTTPS with TLS transport encryption."
                    if is_encrypted
                    else "Target URL specifies unencrypted HTTP transport. In-transit confidentiality is not guaranteed."
                ),
            )
        )

        # -------------------------------------------------------------
        # 2. Hostname Type Observation (IP literal vs Domain name)
        # -------------------------------------------------------------
        hostname = (parsed.hostname or "").lower()
        is_ip_literal = False
        ip_metadata: Dict[str, Any] = {}

        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip_literal = True
            ip_metadata = {
                "is_ip_literal": True,
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_loopback": ip_obj.is_loopback,
                "is_global": ip_obj.is_global,
            }
            evidence.append(
                EvidenceItemCreate(
                    signal_name="hostname_type",
                    observed_value=f"ipv{ip_obj.version}_literal",
                    structured_data=ip_metadata,
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.OBSERVED,
                    explanatory_notes=(
                        f"Target host is specified as an IPv{ip_obj.version} literal rather than a domain name. "
                        "Direct IP addressing is sometimes used in test labs or evasive targets."
                    ),
                )
            )
        except ValueError:
            # Not an IP address -> Domain name
            evidence.append(
                EvidenceItemCreate(
                    signal_name="hostname_type",
                    observed_value="domain_name",
                    structured_data={"is_ip_literal": False, "hostname": hostname},
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.OBSERVED,
                    explanatory_notes="Target host is a standard dot-separated domain name string.",
                )
            )

        # -------------------------------------------------------------
        # 3. Top-Level Domain (TLD) Extraction
        # -------------------------------------------------------------
        if not is_ip_literal and "." in hostname:
            tld = hostname.split(".")[-1]
            evidence.append(
                EvidenceItemCreate(
                    signal_name="tld_identifier",
                    observed_value=tld,
                    structured_data={"tld": tld, "full_hostname": hostname},
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.OBSERVED,
                    explanatory_notes=f"Observed top-level domain '.{tld}' from hostname syntax.",
                )
            )
        elif is_ip_literal:
            evidence.append(
                EvidenceItemCreate(
                    signal_name="tld_identifier",
                    observed_value=None,
                    structured_data={"reason": "target_is_ip_literal"},
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.ABSENT,
                    explanatory_notes="No top-level domain exists because target host is an IP address literal.",
                )
            )

        # -------------------------------------------------------------
        # 4. Subdomain Depth Calculation
        # -------------------------------------------------------------
        if not is_ip_literal and "." in hostname:
            parts = hostname.split(".")
            # Base domain has 2 parts (e.g. example.com), subdomains add to that
            subdomain_depth = max(0, len(parts) - 2)
            evidence.append(
                EvidenceItemCreate(
                    signal_name="subdomain_depth",
                    observed_value=str(subdomain_depth),
                    structured_data={
                        "depth": subdomain_depth,
                        "label_count": len(parts),
                        "labels": parts,
                    },
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.OBSERVED,
                    explanatory_notes=(
                        f"Target domain contains {subdomain_depth} subdomain level(s) above second-level domain."
                    ),
                )
            )

        # -------------------------------------------------------------
        # 5. Explicit Port Specification
        # -------------------------------------------------------------
        if parsed.port is not None:
            is_standard = parsed.port in STANDARD_PORTS
            evidence.append(
                EvidenceItemCreate(
                    signal_name="explicit_port",
                    observed_value=str(parsed.port),
                    structured_data={
                        "port": parsed.port,
                        "is_standard_web_port": is_standard,
                    },
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.OBSERVED,
                    explanatory_notes=(
                        f"Target explicitly defines port {parsed.port} "
                        f"({'standard' if is_standard else 'non-standard'} web port)."
                    ),
                )
            )
        else:
            evidence.append(
                EvidenceItemCreate(
                    signal_name="explicit_port",
                    observed_value=None,
                    structured_data={"default_scheme_port": 443 if is_encrypted else 80},
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.ABSENT,
                    explanatory_notes="Target URL does not specify an explicit port; default scheme port applies.",
                )
            )

        # -------------------------------------------------------------
        # 6. Structural Length Metrics
        # -------------------------------------------------------------
        path_str = parsed.path or "/"
        query_str = parsed.query or ""
        evidence.append(
            EvidenceItemCreate(
                signal_name="url_length_metrics",
                observed_value=f"total={len(url)}, path={len(path_str)}, query={len(query_str)}",
                structured_data={
                    "total_length": len(url),
                    "path_length": len(path_str),
                    "query_length": len(query_str),
                    "path_depth": len([seg for seg in path_str.split("/") if seg]),
                },
                evidence_source=self.name,
                collection_status=EvidenceCollectionStatus.OBSERVED,
                explanatory_notes="Lexical character counts and path segmentation metrics.",
            )
        )

        # -------------------------------------------------------------
        # 7. Sensitive Lexical Keyword Observation
        # -------------------------------------------------------------
        combined_path_query = (path_str + " " + query_str).lower()
        matched = [kw for kw in SENSITIVE_KEYWORDS if kw in combined_path_query]
        if matched:
            evidence.append(
                EvidenceItemCreate(
                    signal_name="sensitive_lexical_tokens",
                    observed_value=", ".join(sorted(matched)),
                    structured_data={"matched_tokens": sorted(matched)},
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.OBSERVED,
                    explanatory_notes=(
                        f"Observed authentication or sensitive keyword tokens ({', '.join(sorted(matched))}) "
                        "in URL path or query string. This is a descriptive syntactic observation, not evidence of malicious intent."
                    ),
                )
            )
        else:
            evidence.append(
                EvidenceItemCreate(
                    signal_name="sensitive_lexical_tokens",
                    observed_value=None,
                    structured_data={"matched_tokens": []},
                    evidence_source=self.name,
                    collection_status=EvidenceCollectionStatus.ABSENT,
                    explanatory_notes="No common authentication or account-related keyword tokens were observed in the path or query string.",
                )
            )

        return evidence
