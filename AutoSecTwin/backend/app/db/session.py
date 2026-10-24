"""SQLAlchemy database session and engine setup for SQLite."""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# Configure SQLite engine with check_same_thread=False for multithreaded ASGI workers
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and safely closes it upon completion."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables on application initialization and apply non-destructive column migrations."""
    # Import models here so Base knows about them before create_all
    import app.models.analysis  # noqa: F401
    import app.models.evidence  # noqa: F401
    import app.models.os_asset  # noqa: F401
    import app.models.os_assessment  # noqa: F401
    import app.models.os_evidence  # noqa: F401
    import app.models.os_finding  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # Lightweight non-destructive column migration for existing SQLite databases
    if settings.DATABASE_URL.startswith("sqlite"):
        from sqlalchemy import text

        with engine.connect() as connection:
            # Check os_assets for owner_id column
            try:
                res = connection.execute(text("PRAGMA table_info(os_assets)"))
                cols = [row[1] for row in res.fetchall()]
                if cols and "owner_id" not in cols:
                    connection.execute(text("ALTER TABLE os_assets ADD COLUMN owner_id VARCHAR(100)"))
                    connection.commit()
            except Exception:
                pass

            # Check os_assessments for owner_id column
            try:
                res = connection.execute(text("PRAGMA table_info(os_assessments)"))
                cols = [row[1] for row in res.fetchall()]
                if cols and "owner_id" not in cols:
                    connection.execute(text("ALTER TABLE os_assessments ADD COLUMN owner_id VARCHAR(100)"))
                    connection.commit()
            except Exception:
                pass
