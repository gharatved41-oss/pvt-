import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_user_otp_request_and_verify():
    email = "test.security.analyst@sentinalx.io"
    # 1. Request OTP
    req_res = client.post("/api/v1/auth/request-code", json={"identifier": email})
    assert req_res.status_code == 200
    req_data = req_res.json()
    assert req_data["status"] == "dispatched"
    assert req_data["passcode"] is not None
    passcode = req_data["passcode"]
    assert passcode.startswith("SX-")

    # 2. Verify with invalid code
    bad_verify = client.post("/api/v1/auth/verify-code", json={"identifier": email, "passcode": "SX-000000"})
    assert bad_verify.status_code == 401

    # 3. Verify with valid code
    good_verify = client.post("/api/v1/auth/verify-code", json={"identifier": email, "passcode": passcode})
    assert good_verify.status_code == 200
    user_data = good_verify.json()["user"]
    assert user_data["email"] == email
    assert user_data["role"] == "user"


def test_developer_passcode_never_leaked():
    dev_username = "mayank.patil"
    # Request code for developer
    req_res = client.post("/api/v1/auth/request-code", json={"identifier": dev_username})
    assert req_res.status_code == 200
    req_data = req_res.json()
    assert req_data["status"] == "developer_auth_required"
    # Crucial security test: passcode must NEVER be leaked
    assert req_data.get("passcode") is None


def test_developer_auth_verification():
    dev_username = "mayank.patil"
    
    # 1. Try with wrong password
    bad_res = client.post("/api/v1/auth/verify-code", json={"identifier": dev_username, "passcode": "WRONG_SECRET"})
    assert bad_res.status_code == 401
    assert "Invalid developer clearance passcode" in bad_res.json()["detail"]

    # 2. Try with valid developer passcode
    good_res = client.post("/api/v1/auth/verify-code", json={"identifier": dev_username, "passcode": "SX-DEV-MAYANK-1337"})
    assert good_res.status_code == 200
    auth_data = good_res.json()
    assert auth_data["user"]["role"] == "developer"
    assert auth_data["user"]["name"] == "Mayank Patil"
