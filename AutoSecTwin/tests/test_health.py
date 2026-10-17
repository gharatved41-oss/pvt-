"""Unit and integration tests for GET /api/v1/health."""

from fastapi.testclient import TestClient


def test_health_endpoint_status_code(client: TestClient) -> None:
    """Verify that GET /api/v1/health returns HTTP 200 OK."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200


def test_health_endpoint_payload_structure(client: TestClient) -> None:
    """Verify that GET /api/v1/health returns the expected keys and values."""
    response = client.get("/api/v1/health")
    data = response.json()

    assert "app_name" in data
    assert "status" in data
    assert "api_version" in data

    assert data["app_name"] == "VulnTwin AI"
    assert data["status"] == "healthy"
    assert data["api_version"] == "v1"


def test_health_endpoint_content_type(client: TestClient) -> None:
    """Verify response Content-Type is application/json."""
    response = client.get("/api/v1/health")
    assert "application/json" in response.headers.get("content-type", "")
