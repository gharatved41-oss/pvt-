"""Controlled Seed Demo Data for Presentation & Verification.
Explicitly flagged as `is_demo=True` and labeled 'DEVELOPMENT DEMO DATA'.
Demonstrates historical progression over multiple days, SafePath alternative, and memory deltas.
"""
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from backend.app.models.database import (
    Analysis, Indicator, Evidence, ProviderResult,
    Recommendation, AnalysisComparison, SafePathRecommendation, SystemEvent
)
from backend.app.db.session import SessionLocal
from backend.app.core.logging import logger


def seed_demo_data():
    db: Session = SessionLocal()
    try:
        # Check if already seeded
        existing_demo = db.query(Analysis).filter(Analysis.is_demo == True).first()
        if existing_demo:
            logger.info("Demo data already seeded.")
            return

        now = datetime.now(timezone.utc)
        t_day1 = now - timedelta(days=3)
        t_day2 = now - timedelta(days=2)
        t_day3 = now - timedelta(days=1)
        t_current = now - timedelta(hours=2)

        # -------------------------------------------------------------
        # DEMO SCENARIO 1: Historical Progression of Suspicious VLC Dropper
        # Target: http://vlc-fast-updater.xyz/vlc_setup.exe
        # -------------------------------------------------------------
        url_target = "http://vlc-fast-updater.xyz/vlc_setup.exe"
        domain_target = "vlc-fast-updater.xyz"

        # Snapshot 1: Day 1 (Risk: 42 / GUARDED)
        id1 = "AST-DEMO-VLC-01"
        a1 = Analysis(
            analysis_id=id1,
            indicator_type="URL",
            submitted_url=url_target,
            normalized_url=url_target,
            domain=domain_target,
            hostname="vlc-fast-updater.xyz",
            scheme="http",
            path="/vlc_setup.exe",
            risk_score=42,
            risk_level="GUARDED",
            confidence=0.70,
            exploitability_level="MEDIUM",
            verdict="SUSPICIOUS",
            status="COMPLETED",
            summary="Initial telemetry identified unregistered third-party domain serving executable.",
            duration_ms=310,
            is_demo=True,
            created_at=t_day1
        )
        db.add(a1)

        # Snapshot 2: Day 2 (Risk: 68 / SUSPICIOUS)
        id2 = "AST-DEMO-VLC-02"
        a2 = Analysis(
            analysis_id=id2,
            indicator_type="URL",
            submitted_url=url_target,
            normalized_url=url_target,
            domain=domain_target,
            hostname="vlc-fast-updater.xyz",
            scheme="http",
            path="/vlc_setup.exe",
            risk_score=68,
            risk_level="SUSPICIOUS",
            confidence=0.82,
            exploitability_level="HIGH",
            verdict="SUSPICIOUS",
            status="COMPLETED",
            summary="Elevated telemetry observed: High-abuse .xyz TLD combined with direct installer distribution.",
            duration_ms=280,
            is_demo=True,
            created_at=t_day2
        )
        db.add(a2)
        db.add(AnalysisComparison(
            current_analysis_id=id2,
            previous_analysis_id=id1,
            risk_delta=26,
            verdict_changed=False,
            previous_verdict="SUSPICIOUS",
            current_verdict="SUSPICIOUS",
            previous_risk_score=42,
            current_risk_score=68,
            summary="Risk increased by +26 points since Day 1 analysis."
        ))

        # Snapshot 3: Day 3 (Risk: 89 / HIGH - MALICIOUS)
        id3 = "AST-DEMO-VLC-03"
        a3 = Analysis(
            analysis_id=id3,
            indicator_type="URL",
            submitted_url=url_target,
            normalized_url=url_target,
            domain=domain_target,
            hostname="vlc-fast-updater.xyz",
            scheme="http",
            path="/vlc_setup.exe",
            risk_score=89,
            risk_level="HIGH",
            confidence=0.94,
            exploitability_level="HIGH",
            verdict="MALICIOUS",
            status="COMPLETED",
            summary="AutoSecTwin confirmed high-confidence malicious dropper activity targeting VLC brand. Multiple telemetry providers flagged malicious payload.",
            duration_ms=340,
            is_demo=True,
            created_at=t_current
        )
        db.add(a3)
        db.add(AnalysisComparison(
            current_analysis_id=id3,
            previous_analysis_id=id2,
            risk_delta=21,
            verdict_changed=True,
            previous_verdict="SUSPICIOUS",
            current_verdict="MALICIOUS",
            previous_risk_score=68,
            current_risk_score=89,
            summary="Risk increased by +21 points. Verdict escalated from SUSPICIOUS to MALICIOUS due to new threat telemetry."
        ))

        # Add Evidence for Snapshot 3
        db.add(Evidence(
            analysis_id=id3,
            category="threat_intel",
            title="Malicious Classification by Threat Intelligence",
            description="Signature confirmed trojanized installer distributing unauthorized secondary stage.",
            source="AutoSecTwin Native Reputation Engine",
            severity="CRITICAL",
            impact_score=40,
            observed_at=t_current
        ))
        db.add(Evidence(
            category="url_signals",
            analysis_id=id3,
            title="Brand Impersonation Detected (VLC)",
            description="Domain 'vlc-fast-updater.xyz' mimics VideoLAN project without legitimate authority.",
            source="Heuristic Classifier",
            severity="HIGH",
            impact_score=20,
            observed_at=t_current
        ))
        db.add(Evidence(
            analysis_id=id3,
            category="url_signals",
            title="Direct Executable Payload Target",
            description="Path '/vlc_setup.exe' references direct binary executable.",
            source="Static Path Analyzer",
            severity="HIGH",
            impact_score=22,
            observed_at=t_current
        ))

        # SafePath Recommendation for Snapshot 3
        db.add(SafePathRecommendation(
            analysis_id=id3,
            software_name="VLC media player",
            original_url=url_target,
            original_risk=89,
            recommended_name="Official VLC media player (VideoLAN Project)",
            recommended_url="https://www.videolan.org/vlc/",
            recommended_domain="videolan.org",
            recommended_risk=5,
            trust_level="VERIFIED_OFFICIAL",
            comparison_reason="Submitted URL distributes VLC from unverified third-party host with known malicious signals. VideoLAN's authentic distribution is HTTPS verified.",
            disclaimer="Lower risk based on available evidence. No download can be guaranteed 100% safe."
        ))

        # Contextual Recommendations
        db.add(Recommendation(
            analysis_id=id3,
            priority="CRITICAL",
            title="Block 'vlc-fast-updater.xyz' at perimeter DNS sinkhole",
            reason="Confirmed high-risk malicious dropper active against end users.",
            action="Apply DNS sinkhole for domain across internal resolvers.",
            effort="LOW",
            coverage="Protects enterprise workstations from connecting to dropper host."
        ))
        db.add(Recommendation(
            analysis_id=id3,
            priority="HIGH",
            title="SafePath: Direct user to official VideoLAN distribution",
            reason="User intends to obtain VLC media player safely.",
            action="Obtain installer from verified vendor at https://www.videolan.org/vlc/.",
            effort="LOW",
            coverage="Ensures user receives authenticated, cryptographically signed binaries."
        ))

        # -------------------------------------------------------------
        # DEMO SCENARIO 2: Phishing Indicator
        # Target: https://secure-chase-verification.top/login.php
        # -------------------------------------------------------------
        id_phish = "AST-DEMO-PHISH-01"
        a_phish = Analysis(
            analysis_id=id_phish,
            indicator_type="URL",
            submitted_url="https://secure-chase-verification.top/login.php",
            normalized_url="https://secure-chase-verification.top/login.php",
            domain="secure-chase-verification.top",
            hostname="secure-chase-verification.top",
            scheme="https",
            path="/login.php",
            risk_score=86,
            risk_level="HIGH",
            confidence=0.91,
            exploitability_level="HIGH",
            verdict="MALICIOUS",
            status="COMPLETED",
            summary="Credential harvesting landing page spoofing Chase Financial banking services.",
            duration_ms=295,
            is_demo=True,
            created_at=t_day1
        )
        db.add(a_phish)
        db.add(Evidence(
            analysis_id=id_phish,
            category="url_signals",
            title="Financial Brand Impersonation (Chase)",
            description="Domain mimics Chase Bank credentials interface.",
            source="Heuristic Classifier",
            severity="HIGH",
            impact_score=35,
            observed_at=t_day1
        ))

        # -------------------------------------------------------------
        # DEMO SCENARIO 3: Clean Indicator (Official VideoLAN)
        # Target: https://www.videolan.org/vlc/
        # -------------------------------------------------------------
        id_clean = "AST-DEMO-CLEAN-01"
        a_clean = Analysis(
            analysis_id=id_clean,
            indicator_type="URL",
            submitted_url="https://www.videolan.org/vlc/",
            normalized_url="https://www.videolan.org/vlc/",
            domain="videolan.org",
            hostname="www.videolan.org",
            scheme="https",
            path="/vlc/",
            risk_score=4,
            risk_level="LOW",
            confidence=0.88,
            exploitability_level="LOW",
            verdict="SAFE",
            status="COMPLETED",
            summary="Authentic, canonical distribution portal for VideoLAN organization.",
            duration_ms=210,
            is_demo=True,
            created_at=t_day2
        )
        db.add(a_clean)

        # -------------------------------------------------------------
        # DEMO SCENARIO 4: Unknown / Insufficient Evidence Indicator
        # Target: https://internal-audit-candidate-04.net/summary
        # -------------------------------------------------------------
        id_unk = "AST-DEMO-UNK-01"
        a_unk = Analysis(
            analysis_id=id_unk,
            indicator_type="URL",
            submitted_url="https://internal-audit-candidate-04.net/summary",
            normalized_url="https://internal-audit-candidate-04.net/summary",
            domain="internal-audit-candidate-04.net",
            hostname="internal-audit-candidate-04.net",
            scheme="https",
            path="/summary",
            risk_score=15,
            risk_level="LOW",
            confidence=0.35,
            exploitability_level="UNKNOWN",
            verdict="UNKNOWN",
            status="COMPLETED",
            summary="Telemetry is insufficient to establish reputation; not marked safe prematurely.",
            duration_ms=190,
            is_demo=True,
            created_at=t_day3
        )
        db.add(a_unk)

        db.commit()
        logger.info("Demo data seeded successfully with realistic historical delta timeline.")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to seed demo data: {str(e)}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_data()
