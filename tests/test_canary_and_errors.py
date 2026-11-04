"""No credential in any response, log or error (canary tokens), and the one error shape."""

from __future__ import annotations

import logging
import uuid

import pytest
from fastapi.testclient import TestClient

from patchwarden.logging_setup import RedactingFilter

from .conftest import demo


class Recorder:
    """Collects every response body and header for the leak check."""

    def __init__(self, client: TestClient):
        self.client = client
        self.seen: list[str] = []

    def __call__(self, method: str, url: str, **kw):
        r = self.client.request(method, url, **kw)
        self.seen.append(r.text)
        self.seen.extend(f"{k}: {v}" for k, v in r.headers.items())
        return r


def test_canary_credentials_never_leak(client, settings, caplog):
    canary = f"CANARY-{uuid.uuid4().hex}"
    wrong = f"CANARY-WRONG-{uuid.uuid4().hex}"
    email = "canary@example.com"

    @client.app.get("/__boom")
    def boom():  # an unexpected crash whose message carries the canary
        raise RuntimeError(f"db said: password={canary}")

    call = Recorder(client)
    with caplog.at_level(logging.DEBUG):
        assert call("POST", "/api/auth/register", json={"email": email, "password": canary}).status_code == 201
        assert call("POST", "/api/auth/register", json={"email": email, "password": canary}).status_code == 409
        assert call("POST", "/api/auth/register", json={"email": "x@example.com", "password": canary[:8]}).status_code == 422
        assert call("POST", "/api/auth/register", json={"email": "not-an-email", "password": canary}).status_code == 422
        assert call("POST", "/api/auth/login", json={"email": email, "password": wrong}).status_code == 401
        assert call("POST", "/api/auth/login", content=f'{{"email": "{email}", "password": "{canary}"',
                    headers={"Content-Type": "application/json"}).status_code == 422
        token = call("POST", "/api/auth/login", json={"email": email, "password": canary}).json()["access_token"]
        auth = {"Authorization": f"Bearer {token}"}

        scan = call("POST", "/api/scans", json={"domain": demo("php84-unpatched")}, headers=auth).json()["scans"][0]
        call("GET", f"/api/scans/{scan['id']}", headers=auth)
        share = call("GET", f"/api/scans/{scan['id']}/share", headers=auth).json()["url"]
        call("GET", share.replace("http://testserver", ""), headers={"Accept": "text/html"})
        call("POST", "/api/sites", json={"domain": "example.org"}, headers=auth)
        call("GET", "/api/sites", headers=auth)
        call("GET", "/api/scans/999", headers={"Authorization": f"Bearer {canary}"})
        r = call("GET", "/__boom")
        assert r.status_code == 500
        assert r.json() == {"error": "internal_error", "message": "Something went wrong on our side. Please try again."}

    responses = "\n".join(call.seen)
    logs = caplog.text + "\n".join(str(rec.__dict__) for rec in caplog.records)
    for secret in (canary, wrong, settings.jwt_secret, settings.credential_key):
        assert secret not in responses
        assert secret not in logs
    # The crash was logged, by type only.
    assert "Unhandled RuntimeError on GET /__boom" in caplog.text

    with client.app.state.sessionmaker() as db:
        from patchwarden.models import AuditLog, User
        user = db.query(User).filter_by(email=email).one()
        assert canary not in user.password_hash and user.password_hash.startswith("$2")
        assert all(canary not in str(a.detail) for a in db.query(AuditLog).all())


def test_redacting_filter_scrubs_known_secrets_and_tokens():
    f = RedactingFilter(["supersecretvalue123"])
    rec = logging.LogRecord("x", logging.INFO, __file__, 1,
                            'GET /scans/1?token=abc.def.ghi key=%s Authorization: Bearer xyz "password": "hunter22"',
                            ("supersecretvalue123",), None)
    f.filter(rec)
    msg = rec.getMessage()
    assert "abc.def.ghi" not in msg and "supersecretvalue123" not in msg
    assert "xyz" not in msg and "hunter22" not in msg


@pytest.mark.parametrize("method,url,kw,status,code", [
    ("GET", "/nope", {}, 404, "not_found"),
    ("DELETE", "/api/scans", {}, 405, "method_not_allowed"),
    ("POST", "/api/auth/register", {"json": {"email": "a@b.co"}}, 422, "invalid_request"),
    ("POST", "/api/scans", {"content": b"{not json", "headers": {"Content-Type": "application/json"}}, 422, "invalid_request"),
    ("POST", "/api/scans", {"json": {}}, 422, "invalid_request"),
    ("GET", "/api/sites", {}, 401, "unauthorized"),
    ("GET", "/api/sites", {"headers": {"Authorization": "Bearer junk"}}, 401, "invalid_token"),
    ("GET", "/api/scans/1", {}, 401, "unauthorized"),
    ("GET", "/api/scans/abc", {}, 422, "invalid_request"),
    ("POST", "/api/scans", {"json": {"domain": "   "}}, 422, "no_domains"),
])
def test_every_error_has_the_same_shape(client, method, url, kw, status, code):
    r = client.request(method, url, **kw)
    assert r.status_code == status
    body = r.json()
    assert set(body) == {"error", "message"}
    assert body["error"] == code
    assert body["message"] and "Traceback" not in body["message"]


def test_validation_error_names_fields_not_values(client):
    r = client.post("/api/auth/register", json={"email": "a@b.co", "password": "short-pw"})
    assert r.json() == {"error": "invalid_request", "message": "Some fields are missing or invalid: password."}


def test_csv_limits(client, settings, auth_headers):
    too_many = "\n".join(f"site{n}.example" for n in range(settings.scan_bulk_max + 1)).encode()
    r = client.post("/api/scans", files={"file": ("s.csv", too_many, "text/csv")}, headers=auth_headers)
    assert r.status_code == 413 and r.json()["error"] == "too_many_domains"
    r = client.post("/api/scans", files={"file": ("s.csv", b"\xff\xfe\x00bad", "text/csv")}, headers=auth_headers)
    assert r.status_code == 400 and r.json()["error"] == "invalid_csv"


def test_redaction_keeps_uvicorn_access_log_args_intact():
    f = RedactingFilter([])
    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                            ("127.0.0.1:5000", "GET", "/scans/1?token=abc.def.ghi", "1.1", 200), None)
    f.filter(rec)
    assert isinstance(rec.args, tuple) and rec.args[4] == 200
    assert rec.getMessage() == '127.0.0.1:5000 - "GET /scans/1?token=<redacted> HTTP/1.1" 200'
