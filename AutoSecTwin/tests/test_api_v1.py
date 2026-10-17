"""Unit and integration tests for API v1 root and error handling."""

from fastapi.testclient import TestClient


def test_api_v1_info_endpoint(client: TestClient) -> None:
    """Verify that GET /api/v1 returns HTTP 200 and required metadata."""
    response = client.get("/api/v1")
    assert response.status_code == 200
    data = response.json()

    assert data["app_name"] == "VulnTwin AI"
    assert data["api_version"] == "v1"
    assert data["docs_url"] == "/docs"
    assert data["health_url"] == "/api/v1/health"
    assert data["status"] == "operational"


def test_api_v1_info_endpoint_with_trailing_slash(client: TestClient) -> None:
    """Verify that GET /api/v1/ returns HTTP 200 and required metadata."""
    response = client.get("/api/v1/")
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "VulnTwin AI"



def test_service_root_endpoint(client: TestClient) -> None:
    """Verify that GET / returns HTTP 200 and navigation references."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()

    assert data["app_name"] == "VulnTwin AI"
    assert data["api_version"] == "v1"
    assert "docs_url" in data
    assert "api_v1_url" in data


def test_custom_404_error_handler(client: TestClient) -> None:
    """Verify that non-existent paths return structured 404 JSON."""
    response = client.get("/api/v1/non-existent-endpoint")
    assert response.status_code == 404
    data = response.json()

    assert data["status_code"] == 404
    assert data["error"] == "HTTP Error"
    assert "Not Found" in data["message"]
    assert data["path"] == "/api/v1/non-existent-endpoint"
