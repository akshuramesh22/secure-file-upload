import io, sys, pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from app import create_app

PDF = b"%PDF-1.4\n%test\n"

@pytest.fixture
def client(tmp_path):
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False,
                      "RATELIMIT_ENABLED": False,
                      "DATABASE": str(tmp_path / "t.db"),
                      "UPLOAD_DIR": str(tmp_path / "up")})
    return app.test_client()

def signup(c, u="alice", p="longpassword1"):
    c.post("/register", data={"username": u, "password": p})
    c.post("/login", data={"username": u, "password": p})

def up(c, name, data):
    return c.post("/upload", data={"file": (io.BytesIO(data), name)},
                  content_type="multipart/form-data", follow_redirects=True)

def test_requires_login(client):
    assert client.get("/").status_code == 302

def test_valid_upload(client):
    signup(client)
    assert b"Uploaded" in up(client, "cv.pdf", PDF).data

def test_rejects_bad_extension(client):
    signup(client)
    assert b"not allowed" in up(client, "evil.exe", b"MZ...").data

def test_rejects_fake_pdf(client):
    signup(client)
    assert b"does not match" in up(client, "fake.pdf", b"<?php system($_GET[1]);").data

def test_path_traversal_name_sanitised(client):
    signup(client)
    up(client, "../../etc/passwd.pdf", PDF)
    assert b"passwd.pdf" in client.get("/").data

def test_other_user_cannot_download(client):
    signup(client, "alice"); up(client, "a.pdf", PDF)
    client.post("/logout")
    signup(client, "bobby")
    assert client.get("/download/1").status_code == 404

def test_download_headers(client):
    signup(client); up(client, "a.pdf", PDF)
    r = client.get("/download/1")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "attachment" in r.headers["Content-Disposition"]
