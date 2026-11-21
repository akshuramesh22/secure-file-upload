# Secure File Upload System

Flask web app where users register, log in, and upload/download/delete their own files safely.

## Run
```
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
flask --app app run
pytest -q
```
Set `HTTPS=1` behind TLS so session cookies get the `Secure` flag.

## Threats and controls
| Threat | Control |
|---|---|
| Malicious file types (.exe, .php) | Extension allowlist (pdf/png/jpg) |
| Renamed files (shell.php -> .pdf) | Magic-byte check of content vs extension |
| Path traversal (`../../x`) | `secure_filename` + random UUID storage names |
| Script execution of uploads | Stored outside static/web root; served only as attachment with fixed MIME + `nosniff` |
| DoS by huge uploads | 5 MB `MAX_CONTENT_LENGTH`, rate limits |
| Brute-force login | 5/min limit, generic error, salted hash (Werkzeug) |
| Session fixation/hijack | `session.clear()` on login, HttpOnly, SameSite, Secure, 30 min expiry |
| CSRF | Flask-WTF tokens on every POST |
| XSS | Jinja autoescape + CSP header |
| IDOR (access others' files) | Every query filtered by `owner_id`; 404 on mismatch |
| SQL injection | Parameterised queries only |
| Malware | Optional ClamAV (`clamscan`) hook |
| Tampering / forensics | SHA-256 stored per file; `audit.log` of all events |

## Known limitations / future work
- Add ClamAV daemon, S3 storage with server-side encryption, 2FA, email verification
- Re-encode images (Pillow) to strip embedded payloads
- Use Redis for rate-limit storage in production; Postgres instead of SQLite
- Add per-user storage quota
