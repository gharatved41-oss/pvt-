import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.core.security import get_password_hash
from app.models.models import User
from main import app

# Use isolated SQLite database for automated testing
TEST_DATABASE_URL = "sqlite:///./test_vuln_twin.db"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    # Seed admin user
    db = TestingSessionLocal()
    admin = db.query(User).filter(User.email == "testadmin@vulntwin.com").first()
    if not admin:
        admin = User(
            email="testadmin@vulntwin.com",
            hashed_password=get_password_hash("TestAdmin@123"),
            full_name="Test Suite Admin",
            role="admin",
            is_active=True
        )
        db.add(admin)
        db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def auth_headers(client):
    res = client.post("/api/v1/auth/login", json={
        "email": "testadmin@vulntwin.com",
        "password": "TestAdmin@123"
    })
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
