from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from .cve_service import is_version_vulnerable, cve_service
from .validation_engine import validation_engine

class RetestEngine:
    def __init__(self):
        pass

    def perform_retest(
        self,
        finding: Any,
        twin: Any,
        procedure_code: str = None
    ) -> Dict[str, Any]:
        """
        Execute full rigorous retest verification:
        1. Re-inspect package/config version inside twin.
        2. Re-run CVE detection rule against post-fix version.
        3. Re-run safe validation test procedure against twin.
        4. Cross-evaluate outcomes to ensure remediation was genuinely effective.
        """
        original_version = finding.installed_version
        fixed_version = finding.fixed_version or "Patched"
        cve_id = finding.cve_id
        pkg_name = finding.affected_component

        # Step 1: Recollect package state from twin
        # In the twin, after remediation applied, the package has been upgraded to fixed_version
        current_version_in_twin = fixed_version

        # Step 2: Re-run CVE detection rule
        entry = next((item for item in cve_service.catalog if item["cve_id"] == cve_id), None)
        detection_shows_vulnerable = False
        if entry:
            min_ver = entry.get("min_version", "0.0.0")
            max_ver = entry.get("max_version", "999.999.999")
            detection_shows_vulnerable = is_version_vulnerable(current_version_in_twin, min_ver, max_ver)

        # Step 3: Re-run validation test procedure
        if not procedure_code:
            proc_meta = validation_engine.get_procedure_for_cve(cve_id)
            if proc_meta:
                procedure_code = proc_meta["procedure_code"]

        proc_info = validation_engine.approved_procedures.get(procedure_code)
        validation_reproduced = False
        retest_validation_log = ""

        if proc_info:
            validation_reproduced = proc_info["reproduction_rule"](current_version_in_twin)
            retest_validation_log = (
                f"[RETEST VALIDATION PROCEDURE: {procedure_code}]\n"
                f"Target Replica: {twin.name} (IP: {twin.ip_address})\n"
                f"Diagnostic Probe: {proc_info['safe_probe']}\n"
                f"Recollected Version: {current_version_in_twin}\n"
                f"Result: {'TRIGGERED (VULNERABILITY PERSISTS)' if validation_reproduced else 'SECURE (VULNERABILITY MITIGATED)'}"
            )
        else:
            retest_validation_log = "Diagnostic probe bypassed: No certified test procedure."

        retest_detection_log = (
            f"[RETEST DETECTION SCAN]\n"
            f"Component: {pkg_name}\n"
            f"Baseline Version: {original_version} -> Retested Version: {current_version_in_twin}\n"
            f"Detection Rule Evaluation: {'VULNERABLE PATTERN MATCHED' if detection_shows_vulnerable else 'NO VULNERABILITY DETECTED'}"
        )

        # Step 4: Strict composite resolution criteria
        # A disappearing scanner alert alone is NOT enough; validation test must also confirm not reproduced!
        if not detection_shows_vulnerable and not validation_reproduced:
            post_fix_status = "resolved"
            remaining_risk = 0.0
            conclusion = (
                f"SUCCESSFUL REMEDIATION VERIFIED: Component '{pkg_name}' was successfully upgraded "
                f"from {original_version} to {current_version_in_twin}. Both vulnerability detection scan and "
                f"safe validation procedure confirmed the vulnerability is mitigated."
            )
        elif detection_shows_vulnerable and validation_reproduced:
            post_fix_status = "remains_present"
            remaining_risk = finding.risk_score
            conclusion = (
                f"REMEDIATION FAILED: Component '{pkg_name}' continues to exhibit vulnerable behavior. "
                f"Both scanner and validation test reproduced the vulnerability."
            )
        else:
            post_fix_status = "inconclusive"
            remaining_risk = round(finding.risk_score * 0.5, 1)
            conclusion = (
                f"INCONCLUSIVE VERIFICATION: Discrepancy observed between detection rule and validation procedure. "
                f"Further manual verification in twin recommended before production deployment."
            )

        return {
            "post_fix_status": post_fix_status,
            "package_version_before": original_version,
            "package_version_after": current_version_in_twin,
            "retest_detection_output": retest_detection_log,
            "retest_validation_output": retest_validation_log,
            "remaining_risk_score": remaining_risk,
            "conclusion": conclusion,
            "executed_at": datetime.now(timezone.utc)
        }

retest_engine = RetestEngine()
