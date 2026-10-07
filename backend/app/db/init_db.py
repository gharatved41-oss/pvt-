"""Database initialization routines.
Creates all SQLite tables and composite indexes safely on startup.
"""
from backend.app.db.session import engine, Base
from backend.app.models.database import (
    Analysis, Indicator, Evidence, ProviderResult,
    Recommendation, AnalysisComparison, SafePathRecommendation, SystemEvent,
    UserDailyQuota
)
from backend.app.core.logging import logger


def init_database():
    """Initializes database schema and ensures all tables exist."""
    logger.info("Initializing AutoSecTwin SQLite schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("AutoSecTwin database schema initialized successfully.")


if __name__ == "__main__":
    init_database()
