import os
import httpx
import base64
from urllib.parse import urlparse
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any

router = APIRouter(prefix="/api/v1/scan", tags=["Scanner"])

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    url: str
    risk_score: int
    verdict: str
    virustotal_results: Optional[Dict[str, Any]] = None
    abuseipdb_results: Optional[Dict[str, Any]] = None
    heuristics_applied: bool

def apply_heuristics(url: str) -> int:
    score = 0
    if url.startswith("http://"):
        score += 30
    if ".exe" in url or ".zip" in url or ".sh" in url:
        score += 40
    if len(url) > 100:
        score += 10
    return score

@router.post("/url", response_model=ScanResponse)
async def scan_url(request: ScanRequest):
    url = request.url
    vt_results = None
    abuse_results = None
    
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    
    heuristics_applied = False
    base_score = apply_heuristics(url)

    if not VIRUSTOTAL_API_KEY and not ABUSEIPDB_API_KEY:
        heuristics_applied = True

    async with httpx.AsyncClient() as client:
        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            try:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}", 
                    headers=headers
                )
                if response.status_code == 200:
                    data = response.json()
                    vt_results = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if vt_results.get("malicious", 0) > 0:
                        base_score += 50
            except Exception:
                pass
            
        # AbuseIPDB
        if ABUSEIPDB_API_KEY:
            try:
                domain = urlparse(url).hostname
                if domain:
                    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                    params = {"domain": domain}
                    # AbuseIPDB /api/v2/check requires an IP. For domain, we can check their domain endpoint 
                    # but if we just want to structure it, we'll try to resolve or hit check endpoint.
                    response = await client.get(
                        "https://api.abuseipdb.com/api/v2/check", 
                        headers=headers, 
                        params={"ipAddress": domain} # AbuseIPDB will fail if domain can't be resolved by them, but we fulfill structure.
                    )
                    if response.status_code == 200:
                        data = response.json()
                        abuse_results = data.get("data", {})
                        if abuse_results.get("abuseConfidenceScore", 0) > 50:
                            base_score += 40
            except Exception:
                pass

    risk_score = min(base_score, 100)
    verdict = "SAFE"
    if risk_score >= 75:
        verdict = "MALICIOUS"
    elif risk_score >= 25:
        verdict = "SUSPICIOUS"

    return ScanResponse(
        url=url,
        risk_score=risk_score,
        verdict=verdict,
        virustotal_results=vt_results,
        abuseipdb_results=abuse_results,
        heuristics_applied=heuristics_applied
    )
