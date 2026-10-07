"""AutoSecTwin SafePath — Evidence-Based Safer Alternative Recommendation Engine.
Detects user intent from suspicious download/software URLs, queries an allowlisted
catalog of authentic vendor sources, validates reputation, and presents verified lower-risk alternatives.
Never automatically downloads any payload.
"""
from typing import Optional, Dict, Any
from backend.app.schemas.analysis import SafePathAlternative
from backend.app.core.logging import logger

# Curated catalog of official software vendors and authentic distribution channels
TRUSTED_SOFTWARE_CATALOG = {
    "vlc": {
        "name": "VLC media player",
        "official_domain": "videolan.org",
        "official_url": "https://www.videolan.org/vlc/",
        "vendor": "VideoLAN Project",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 5,
        "keywords": ["vlc", "videolan"],
    },
    "7zip": {
        "name": "7-Zip File Archiver",
        "official_domain": "7-zip.org",
        "official_url": "https://www.7-zip.org/",
        "vendor": "Igor Pavlov / 7-Zip Foundation",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 4,
        "keywords": ["7zip", "7-zip", "7z"],
    },
    "chrome": {
        "name": "Google Chrome Browser",
        "official_domain": "google.com",
        "official_url": "https://www.google.com/chrome/",
        "vendor": "Google LLC",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 6,
        "keywords": ["chrome", "googlechrome"],
    },
    "zoom": {
        "name": "Zoom Workplace Client",
        "official_domain": "zoom.us",
        "official_url": "https://zoom.us/download",
        "vendor": "Zoom Video Communications",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 8,
        "keywords": ["zoom", "zoomus"],
    },
    "notepadplusplus": {
        "name": "Notepad++ Text & Source Editor",
        "official_domain": "notepad-plus-plus.org",
        "official_url": "https://notepad-plus-plus.org/downloads/",
        "vendor": "Don Ho / Notepad++",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 5,
        "keywords": ["notepad++", "notepad-plus-plus", "notepadplusplus", "npp"],
    },
    "putty": {
        "name": "PuTTY SSH & Telnet Client",
        "official_domain": "chiark.greenend.org.uk",
        "official_url": "https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html",
        "vendor": "Simon Tatham",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 5,
        "keywords": ["putty", "puttygen"],
    },
    "python": {
        "name": "Python Programming Language",
        "official_domain": "python.org",
        "official_url": "https://www.python.org/downloads/",
        "vendor": "Python Software Foundation",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 4,
        "keywords": ["python", "python3"],
    },
    "git": {
        "name": "Git SCM",
        "official_domain": "git-scm.com",
        "official_url": "https://git-scm.com/downloads",
        "vendor": "Git Project",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 4,
        "keywords": ["git-scm", "git"],
    },
    "vscode": {
        "name": "Visual Studio Code",
        "official_domain": "code.visualstudio.com",
        "official_url": "https://code.visualstudio.com/Download",
        "vendor": "Microsoft Corporation",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 6,
        "keywords": ["vscode", "visualstudiocode"],
    },
    "keepass": {
        "name": "KeePass Password Safe",
        "official_domain": "keepass.info",
        "official_url": "https://keepass.info/download.html",
        "vendor": "Dominik Reichl",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 5,
        "keywords": ["keepass", "keepass2"],
    },
    "obs": {
        "name": "OBS Studio (Open Broadcaster Software)",
        "official_domain": "obsproject.com",
        "official_url": "https://obsproject.com/download",
        "vendor": "OBS Project",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 5,
        "keywords": ["obs", "obsproject", "obsstudio"],
    },
    "winrar": {
        "name": "WinRAR Compression Utility",
        "official_domain": "rarlab.com",
        "official_url": "https://www.rarlab.com/download.htm",
        "vendor": "win.rar GmbH / Alexander Roshal",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 5,
        "keywords": ["winrar", "rarlab"],
    },
    "firefox": {
        "name": "Mozilla Firefox Browser",
        "official_domain": "mozilla.org",
        "official_url": "https://www.mozilla.org/firefox/new/",
        "vendor": "Mozilla Foundation",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 4,
        "keywords": ["firefox", "mozilla"],
    },
    "wireshark": {
        "name": "Wireshark Network Packet Analyzer",
        "official_domain": "wireshark.org",
        "official_url": "https://www.wireshark.org/download.html",
        "vendor": "Wireshark Foundation",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 4,
        "keywords": ["wireshark"],
    },
    "kmsauto": {
        "name": "Microsoft Genuine Licensing / Open Verification",
        "official_domain": "microsoft.com",
        "official_url": "https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys",
        "vendor": "Microsoft Corporation",
        "trust_level": "VERIFIED_OFFICIAL",
        "baseline_risk": 3,
        "keywords": ["kmsauto", "kmspico", "windows-activator", "crack"],
    }
}



class SafePathEngine:
    """
    Evaluates whether a suspicious indicator mimics known software distributions
    and provides verified, evidence-backed safer alternatives.
    """

    def find_alternative(
        self,
        url: str,
        indicators: Dict[str, Any],
        risk_score: int
    ) -> Optional[SafePathAlternative]:
        """
        Searches the trusted catalog for software matches when risk is elevated or domain is untrusted.
        """
        # If the indicator is already low-risk and canonical, alternative is not necessary
        if risk_score < 25 and not indicators.get("has_executable"):
            return None

        hostname = (indicators.get("hostname") or "").lower()
        path = (indicators.get("path") or "").lower()
        full_text = f"{hostname}/{path}"

        matched_key = None
        for key, entry in TRUSTED_SOFTWARE_CATALOG.items():
            for kw in entry["keywords"]:
                if kw in full_text:
                    matched_key = key
                    break
            if matched_key:
                break

        if not matched_key:
            return None

        entry = TRUSTED_SOFTWARE_CATALOG[matched_key]
        official_domain = entry["official_domain"]

        # If the URL is already the authentic official vendor website, don't flag as alternative needed
        if hostname.endswith(official_domain):
            return None

        # The user has hit an unofficial, repackaged, or suspicious distribution for known software
        reason = (
            f"The submitted URL appears to deliver or reference '{entry['name']}' from an unverified third-party host "
            f"('{indicators.get('domain')}'). Third-party distributors frequently bundle adware, telemetry droppers, "
            f"or backdoored binaries. AutoSecTwin identified the authenticated vendor distribution channel ({official_domain})."
        )

        return SafePathAlternative(
            software_name=entry["name"],
            original_url=url,
            original_risk=risk_score,
            recommended_name=f"Official {entry['name']} ({entry['vendor']})",
            recommended_url=entry["official_url"],
            recommended_domain=entry["official_domain"],
            recommended_risk=entry["baseline_risk"],
            trust_level=entry["trust_level"],
            comparison_reason=reason,
            disclaimer="Lower risk based on available evidence. No download can be guaranteed 100% safe."
        )


safepath_engine = SafePathEngine()
