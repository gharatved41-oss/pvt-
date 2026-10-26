import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models.models import User, Asset, InventorySnapshot, DigitalTwin
from app.api.api_v1 import api_router
from app.services.inventory_parser import InventoryParser
import os
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vuln_twin")

def seed_initial_database():
    """Seed initial administrator and realistic test fixtures on first launch."""
    db = SessionLocal()
    try:
        # 1. Admin user
        admin = db.query(User).filter(User.email == "admin@vulntwin.local").first()
        if not admin:
            admin = User(
                email="admin@vulntwin.local",
                hashed_password=get_password_hash("VulnTwin@2026!"),
                full_name="Lead Cyber Architect",
                role="admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
            logger.info("Initialized default administrator account: admin@vulntwin.local")

        # 2. Demo Assets & Inventories if none exist
        if db.query(Asset).count() == 0:
            fixtures_dir = os.path.join(os.path.dirname(__file__), "app", "fixtures", "sample_inventories")
            
            # Asset 1: Ubuntu Web Gateway
            ubuntu_path = os.path.join(fixtures_dir, "ubuntu_server_inventory.json")
            if os.path.exists(ubuntu_path):
                with open(ubuntu_path, "r", encoding="utf-8") as f:
                    u_data = json.load(f)
                
                asset_ubuntu = Asset(
                    name="Primary Production Web Gateway",
                    ip_address=u_data.get("ip_address", "10.0.4.15"),
                    hostname=u_data.get("hostname", "prod-web-gateway-01"),
                    os_type=u_data.get("os_type", "linux"),
                    os_version=u_data.get("os_version", "Ubuntu 22.04.2 LTS"),
                    environment=u_data.get("environment", "production"),
                    criticality=u_data.get("criticality", "critical"),
                    description="Mission-critical reverse proxy handling public ingress SSL termination."
                )
                db.add(asset_ubuntu)
                db.commit()
                db.refresh(asset_ubuntu)

                # Inventory Snapshot
                snap_ubuntu = InventorySnapshot(
                    asset_id=asset_ubuntu.id,
                    format="json",
                    raw_filename="ubuntu_server_inventory.json",
                    packages_count=len(u_data.get("packages", [])),
                    parsed_packages=u_data.get("packages", []),
                    configuration_metadata=u_data.get("configuration_metadata", {})
                )
                db.add(snap_ubuntu)

                # Default Digital Twin replica for Asset 1
                twin_ubuntu = DigitalTwin(
                    asset_id=asset_ubuntu.id,
                    name=f"Twin-{asset_ubuntu.name}-Lab",
                    provider="mock_isolated",
                    template_name="ubuntu-22.04-cve-lab",
                    status="ready",
                    ip_address="192.168.100.105",
                    network_isolated=True,
                    snapshot_status="baseline-snapshot-created",
                    config_parity_score=99.2,
                    target_config=u_data.get("configuration_metadata", {}),
                    current_config=u_data.get("configuration_metadata", {})
                )
                db.add(twin_ubuntu)
                db.commit()

            # Asset 2: Windows Domain Controller Staging
            win_path = os.path.join(fixtures_dir, "windows_server_inventory.json")
            if os.path.exists(win_path):
                with open(win_path, "r", encoding="utf-8") as f:
                    w_data = json.load(f)

                asset_win = Asset(
                    name="Active Directory Identity Controller",
                    ip_address=w_data.get("ip_address", "10.0.8.20"),
                    hostname=w_data.get("hostname", "win-ad-dc-01"),
                    os_type=w_data.get("os_type", "windows"),
                    os_version=w_data.get("os_version", "Windows Server 2022 Datacenter"),
                    environment=w_data.get("environment", "staging"),
                    criticality=w_data.get("criticality", "critical"),
                    description="Internal authentication server managing Active Directory Domain Services."
                )
                db.add(asset_win)
                db.commit()
                db.refresh(asset_win)

                snap_win = InventorySnapshot(
                    asset_id=asset_win.id,
                    format="json",
                    raw_filename="windows_server_inventory.json",
                    packages_count=len(w_data.get("packages", [])),
                    parsed_packages=w_data.get("packages", []),
                    configuration_metadata=w_data.get("configuration_metadata", {})
                )
                db.add(snap_win)

                twin_win = DigitalTwin(
                    asset_id=asset_win.id,
                    name=f"Twin-{asset_win.name}-Lab",
                    provider="mock_isolated",
                    template_name="win-server2022-lab",
                    status="ready",
                    ip_address="192.168.100.120",
                    network_isolated=True,
                    snapshot_status="baseline-snapshot-created",
                    config_parity_score=97.8,
                    target_config=w_data.get("configuration_metadata", {}),
                    current_config=w_data.get("configuration_metadata", {})
                )
                db.add(twin_win)
                db.commit()

            logger.info("Successfully seeded initial assets, inventory snapshots, and digital twin replicas.")
    except Exception as e:
        logger.error(f"Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables
    Base.metadata.create_all(bind=engine)
    seed_initial_database()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Vuln TWin - AI/ML Digital Twin Security Assessment & Remediation Platform",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r".*",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler to prevent leaking sensitive tracebacks
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. This security event has been logged."}
    )

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "documentation": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
