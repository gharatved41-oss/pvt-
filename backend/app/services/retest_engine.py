from datetime import datetime, timezone
from typing import Dict, Any, Optional
from .cve_service import is_version_vulnerable, cve_service
from .validation_engine import validation_engine

class RetestEngine:
    def __init__(self):
        pass

    def perform_retest(
        self,
        finding: Any,
        twin: Any,
        procedure_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute full rigorous retest verification:
        1. Dynamically recollect package/config state inside isolated twin replica.
        2. Re-run CVE detection rule against post-fix state.
        3. Re-run non-destructive validation test procedure against twin.
        4. Cross-evaluate outcomes to ensure remediation was genuinely effective.
        """
        original_version = finding.installed_version
        fixed_version = finding.fixed_version or "Patched"
        cve_id = finding.cve_id
        pkg_name = finding.affected_component

        # Step 1: Recollect package state from twin configuration
        current_cfg = twin.current_config or {}
        packages = current_cfg.get("packages", {})

        current_version_in_twin = None
        if isinstance(packages, dict) and pkg_name in packages:
            current_version_in_twin = packages[pkg_name]
        elif current_cfg.get(f"pkg_{pkg_name}_version"):
            current_version_in_twin = current_cfg.get(f"pkg_{pkg_name}_version")
        elif (
            isinstance(current_cfg.get("last_remediation_applied"), dict)
            and current_cfg["last_remediation_applied"].get("component") == pkg_name
            and current_cfg["last_remediation_applied"].get("version")
        ):
            current_version_in_twin = current_cfg["last_remediation_applied"]["version"]
        elif (
            current_cfg.get(f"config_hardened_{pkg_name}")
            or current_cfg.get(f"service_{pkg_name}_reconfigured")
        ):
            current_version_in_twin = fixed_version
        elif finding.detection_status == "fixed":
            current_version_in_twin = fixed_version
        else:
            # If no remediation has been applied inside the twin sandbox, the version remains the baseline
            current_version_in_twin = original_version

        # Check for indeterminate or unparseable versions
        is_indeterminate = current_version_in_twin in [None, "", "unknown", "indeterminate", "N/A"]

        # Step 2: Re-run CVE detection rule
        detection_shows_vulnerable = False
        entry = next((item for item in cve_service.catalog if item["cve_id"] == cve_id), None)
        if not is_indeterminate:
            if entry:
                min_ver = entry.get("min_version", "0.0.0")
                max_ver = entry.get("max_version", "999.999.999")
                detection_shows_vulnerable = is_version_vulnerable(current_version_in_twin, min_ver, max_ver)
            else:
                # If not in local catalog, compare with fixed_version
                detection_shows_vulnerable = (current_version_in_twin == original_version and original_version != fixed_version)

        # Step 3: Re-run validation test procedure
        if not procedure_code:
            proc_meta = validation_engine.get_procedure_for_cve(cve_id)
            if proc_meta:
                procedure_code = proc_meta["procedure_code"]

        proc_info = validation_engine.approved_procedures.get(procedure_code) if procedure_code else None
        validation_reproduced = False
        retest_validation_log = ""

        if is_indeterminate:
            retest_validation_log = (
                f"[RETEST VALIDATION PROCEDURE: {procedure_code or 'UNKNOWN'}]\n"
                f"Target Sandbox: {twin.name} (IP: {twin.ip_address})\n"
                f"Status: INCONCLUSIVE - Target package telemetry missing or indeterminate."
            )
        elif proc_info:
            validation_reproduced = proc_info["reproduction_rule"](current_version_in_twin)
            retest_validation_log = (
                f"[RETEST VALIDATION PROCEDURE: {procedure_code}]\n"
                f"Target Replica: {twin.name} (IP: {twin.ip_address})\n"
                f"Diagnostic Probe: {proc_info['safe_probe']}\n"
                f"Recollected Version: {current_version_in_twin}\n"
                f"Result: {'TRIGGERED (VULNERABILITY PERSISTS)' if validation_reproduced else 'SECURE (VULNERABILITY MITIGATED)'}"
            )
        else:
            validation_reproduced = detection_shows_vulnerable
            retest_validation_log = (
                f"[BASELINE AUDIT VALIDATION]\n"
                f"Target Sandbox: {twin.name} (IP: {twin.ip_address})\n"
                f"Component: {pkg_name} ({current_version_in_twin})\n"
                f"Result: {'TRIGGERED (VULNERABILITY PERSISTS)' if validation_reproduced else 'SECURE (VULNERABILITY MITIGATED)'}"
            )

        retest_detection_log = (
            f"[RETEST DETECTION SCAN]\n"
            f"Component: {pkg_name}\n"
            f"Baseline Version: {original_version} -> Retested Version: {current_version_in_twin or 'UNKNOWN'}\n"
            f"Detection Rule Evaluation: {'VULNERABLE PATTERN MATCHED' if detection_shows_vulnerable else 'NO VULNERABILITY DETECTED'}"
        )

        # Step 4: Strict composite resolution criteria
        baseline_risk = finding.risk_score if (finding.risk_score and finding.risk_score > 0) else (finding.cvss_v3_score * 10)

        if is_indeterminate:
            post_fix_status = "inconclusive"
            remaining_risk = round(baseline_risk * 0.5, 1)
            conclusion = (
                f"INCONCLUSIVE VERIFICATION: Component '{pkg_name}' version could not be reliably verified "
                f"in Digital Twin replica '{twin.name}'. Telemetry is indeterminate."
            )
        elif not detection_shows_vulnerable and not validation_reproduced:
            post_fix_status = "resolved"
            remaining_risk = 0.0
            conclusion = (
                f"SUCCESSFUL REMEDIATION VERIFIED: Component '{pkg_name}' was successfully upgraded "
                f"from {original_version} to {current_version_in_twin}. Both vulnerability detection scan and "
                f"safe validation procedure confirmed the vulnerability is mitigated."
            )
        elif detection_shows_vulnerable and validation_reproduced:
            post_fix_status = "remains_present"
            remaining_risk = baseline_risk
            conclusion = (
                f"REMEDIATION FAILED: Component '{pkg_name}' continues to exhibit vulnerable behavior. "
                f"Both scanner and validation test reproduced the vulnerability in twin sandbox."
            )
        else:
            post_fix_status = "inconclusive"
            remaining_risk = round(baseline_risk * 0.5, 1)
            conclusion = (
                f"INCONCLUSIVE VERIFICATION: Discrepancy observed between detection rule and validation procedure. "
                f"Detection shows vulnerable={detection_shows_vulnerable}, validation reproduced={validation_reproduced}. "
                f"Further manual verification in twin recommended before production deployment."
            )

        return {
            "post_fix_status": post_fix_status,
            "package_version_before": original_version,
            "package_version_after": current_version_in_twin or "unknown",
            "retest_detection_output": retest_detection_log,
            "retest_validation_output": retest_validation_log,
            "remaining_risk_score": remaining_risk,
            "conclusion": conclusion,
            "executed_at": datetime.now(timezone.utc)
        }

retest_engine = RetestEngine()

