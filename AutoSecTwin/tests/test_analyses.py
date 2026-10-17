"""Automated tests for target URL submission, validation, storage, and retrieval."""

from fastapi.testclient import TestClient


def test_submit_valid_url(client: TestClient) -> None:
    """Verify that submitting a valid HTTPS URL returns 201 Created with status 'pending'."""
    payload = {"url": "https://example.com/login"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert len(data["id"]) > 0
    assert data["url"] == "https://example.com/login"
    assert data["status"] == "pending"
    assert "created_at" in data


def test_submit_valid_http_url_with_port(client: TestClient) -> None:
    """Verify that submitting a valid HTTP URL with explicit port is accepted and normalized."""
    payload = {"url": "http://api.localtest.org:8080/v1/resource?id=123#frag"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 201
    data = response.json()
    assert data["url"] == "http://api.localtest.org:8080/v1/resource?id=123#frag"
    assert data["status"] == "pending"


def test_submit_unsupported_scheme_ftp(client: TestClient) -> None:
    """Verify rejection of FTP scheme with 422 Unprocessable Entity."""
    payload = {"url": "ftp://ftp.example.com/archive.zip"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 422
    data = response.json()
    assert "Unsupported scheme" in str(data) or "validation" in str(data).lower()


def test_submit_unsupported_scheme_file(client: TestClient) -> None:
    """Verify rejection of file:// scheme."""
    payload = {"url": "file:///etc/passwd"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 422


def test_submit_unsupported_scheme_javascript(client: TestClient) -> None:
    """Verify rejection of javascript: pseudo-protocol."""
    payload = {"url": "javascript:alert(document.cookie)"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 422


def test_submit_url_with_embedded_credentials(client: TestClient) -> None:
    """Verify rejection of URLs with userinfo / credentials."""
    payload = {"url": "https://user:password123@example.com/path"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 422
    assert "embedded user credentials" in str(response.json())


def test_submit_url_with_username_only_credential(client: TestClient) -> None:
    """Verify rejection of URLs with username only (@ embedded)."""
    payload = {"url": "https://admin@example.com/"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 422


def test_submit_url_missing_hostname(client: TestClient) -> None:
    """Verify rejection when hostname is absent."""
    payload = {"url": "http:///path/only"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 422


def test_submit_malformed_url_empty_scheme(client: TestClient) -> None:
    """Verify rejection of raw domain strings missing scheme."""
    payload = {"url": "example.com"}
    response = client.post("/api/v1/analyses", json=payload)

    assert response.status_code == 422


def test_submit_malformed_hostname_dots(client: TestClient) -> None:
    """Verify rejection of malformed hostnames with leading/trailing or double dots."""
    payload = {"url": "http://.example.com"}
    response = client.post("/api/v1/analyses", json=payload)
    assert response.status_code == 422

    payload2 = {"url": "http://example..com"}
    response2 = client.post("/api/v1/analyses", json=payload2)
    assert response2.status_code == 422


def test_get_analysis_by_id_success(client: TestClient) -> None:
    """Verify retrieval of an existing analysis record by ID."""
    # 1. Create a record
    create_res = client.post("/api/v1/analyses", json={"url": "https://cyber-target.io/portal"})
    assert create_res.status_code == 201
    created_id = create_res.json()["id"]

    # 2. Retrieve by ID
    get_res = client.get(f"/api/v1/analyses/{created_id}")
    assert get_res.status_code == 200
    record = get_res.json()

    assert record["id"] == created_id
    assert record["url"] == "https://cyber-target.io/portal"
    assert record["status"] == "pending"
    assert "created_at" in record


def test_get_analysis_by_unknown_id(client: TestClient) -> None:
    """Verify that querying a non-existent ID returns 404 Not Found."""
    response = client.get("/api/v1/analyses/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    data = response.json()
    assert data["status_code"] == 404
    assert "not found" in data["message"].lower()


def test_list_analyses_pagination(client: TestClient) -> None:
    """Verify paginated listing of analysis records."""
    # Create 5 records
    for i in range(5):
        client.post("/api/v1/analyses", json={"url": f"https://example{i}.org"})

    # Query page 1 (limit 2, offset 0)
    page1 = client.get("/api/v1/analyses?limit=2&offset=0")
    assert page1.status_code == 200
    data1 = page1.json()
    assert data1["total"] == 5
    assert len(data1["items"]) == 2
    assert data1["limit"] == 2
    assert data1["offset"] == 0

    # Query page 2 (limit 2, offset 2)
    page2 = client.get("/api/v1/analyses?limit=2&offset=2")
    assert page2.status_code == 200
    data2 = page2.json()
    assert data2["total"] == 5
    assert len(data2["items"]) == 2
    assert data2["offset"] == 2

    # Query beyond range (offset 10)
    page_empty = client.get("/api/v1/analyses?limit=2&offset=10")
    assert page_empty.status_code == 200
    data_empty = page_empty.json()
    assert data_empty["total"] == 5
    assert len(data_empty["items"]) == 0


def test_database_isolation_step_a(client: TestClient) -> None:
    """Test A: Create a record. In-memory DB should start empty."""
    initial_list = client.get("/api/v1/analyses")
    assert initial_list.json()["total"] == 0

    client.post("/api/v1/analyses", json={"url": "https://isolation-test-target.com"})
    updated_list = client.get("/api/v1/analyses")
    assert updated_list.json()["total"] == 1


def test_database_isolation_step_b(client: TestClient) -> None:
    """Test B: Verify database isolation. DB must be clean and not contain Test A's record."""
    fresh_list = client.get("/api/v1/analyses")
    assert fresh_list.json()["total"] == 0
