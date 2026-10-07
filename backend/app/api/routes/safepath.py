"""SafePath Verified Source Catalog API.
Exposes allowlisted vendor sources and integrity profiles for transparent verification.
"""
from fastapi import APIRouter
from backend.app.services.safepath import TRUSTED_SOFTWARE_CATALOG

router = APIRouter()


@router.get("/safepath/catalog")
def get_safepath_catalog():
    """
    Returns list of allowlisted software profiles with verified vendor domains.
    """
    catalog_items = []
    for key, data in TRUSTED_SOFTWARE_CATALOG.items():
        catalog_items.append({
            "key": key,
            "software_name": data["name"],
            "vendor": data["vendor"],
            "official_domain": data["official_domain"],
            "official_url": data["official_url"],
            "trust_level": data["trust_level"],
            "baseline_risk": data["baseline_risk"]
        })
    return {
        "catalog_count": len(catalog_items),
        "disclaimer": "Lower risk based on available evidence. No download can be guaranteed 100% safe.",
        "vendors": catalog_items
    }
