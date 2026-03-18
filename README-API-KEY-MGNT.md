# malhaus API Key Management

API keys are managed entirely via the `manage_keys.py` CLI script on the server. There is no web UI — key issuance requires intentional admin action.

Keys are stored as **SHA-256 hashes** in `maltriage.db`. The plaintext token is printed once at creation time and never persisted. If it is lost, revoke the key and create a new one.

---

## Key format

```
mh_<64 hex characters>
```

- `mh_` — fixed prefix, makes keys identifiable in logs, secrets scanners, and paste sites
- 64 hex chars — 32 random bytes (256-bit entropy) from `secrets.token_hex(32)`

Example:
```
mh_<your-64-hex-token>
```

---

## Database tables

`manage_keys.py` reads and writes three tables in `maltriage.db`:

| Table | Purpose |
|-------|---------|
| `api_keys` | Key metadata and revocation status |
| `api_jobs` | Async analysis jobs submitted via the API |
| `api_rate_limits` | Per-key sliding-window rate limit counters |

Tables are created automatically on first use.

---

## Commands

### Create a key

```bash
python manage_keys.py create --label "LABEL" [--rate-limit N]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--label` | required | Human-readable name — who or what this key is for |
| `--rate-limit` | 60 | Max API requests per hour for this key |

**Example:**

```bash
python manage_keys.py create --label "Alice — SOC team" --rate-limit 30
```

**Output:**

```
  API key created — store this token securely. It will NOT be shown again.

  Token  : mh_<your-64-hex-token>
  Key ID : 227e520f-6020-498a-9954-c48c461b3a33
  Label  : Alice — SOC team
  Rate   : 30 requests/hour

  Usage:
    curl -H "Authorization: Bearer mh_a96c54b3..." ...
```

The **Token** is what you hand to the consumer. The **Key ID** is your admin handle — use it for `revoke`, `info`, and audit logging.

---

### List all keys

```bash
python manage_keys.py list
```

**Output:**

```
  key_id                                label                 status    created              last_used              rate/h
  ------------------------------------------------------------------------------------------------------------------
  227e520f-6020-498a-9954-c48c461b3a33  Alice — SOC team      active    2026-03-16 13:00:00  2026-03-16 14:22:11    30/h
  8f3c9a12-1122-4bcd-a001-aabbccdd0011  CI pipeline           active    2026-01-01 09:00:00  2026-03-15 22:10:05    60/h
  dd44ef01-dead-beef-cafe-112233445566  old intern key        REVOKED   2025-12-01 10:00:00  2025-12-15 08:30:00    10/h
```

`last_used` shows the last time the key successfully authenticated a request. Useful for finding stale or unused keys.

---

### Show key details

```bash
python manage_keys.py info <key_id>
```

**Example:**

```bash
python manage_keys.py info 227e520f-6020-498a-9954-c48c461b3a33
```

**Output:**

```
  Key ID   : 227e520f-6020-498a-9954-c48c461b3a33
  Label    : Alice — SOC team
  Status   : active
  Created  : 2026-03-16 13:00:00
  Last used: 2026-03-16 14:22:11
  Rate     : 30/hour
```

---

### Revoke a key

```bash
python manage_keys.py revoke <key_id>
```

**Example:**

```bash
python manage_keys.py revoke 227e520f-6020-498a-9954-c48c461b3a33
```

Revocation takes effect immediately — the next API request using that token will receive `HTTP 401`. The key row is soft-deleted (flagged `revoked = 1`) and remains visible in `list` with status `REVOKED` for audit purposes.

To fully remove it from the database:

```bash
sqlite3 maltriage.db "DELETE FROM api_keys WHERE key_id = '227e520f-6020-498a-9954-c48c461b3a33'"
```

---

### Clean up old jobs

```bash
python manage_keys.py cleanup-jobs [--days N]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--days` | 30 | Delete completed/failed jobs older than N days |

**Example:**

```bash
python manage_keys.py cleanup-jobs --days 14
```

**Output:**

```
Deleted 47 completed/failed jobs older than 14 days.
```

This only removes rows from `api_jobs` — it does not touch `api_keys`, `web_recents`, or any analysis artifacts.

---

## Recommended practices

### One key per consumer

Issue a separate key for each person, team, or integration. This lets you:
- Revoke a single consumer without affecting others
- See per-consumer usage via `last_used_at`
- Set appropriate rate limits per consumer

### Rate limits

| Consumer | Suggested limit |
|----------|----------------|
| Individual analyst | 10–30/hour |
| Automated CI pipeline | 30–60/hour |
| SOAR / Logic App integration | 60–120/hour |
| MCP agent session | 30–60/hour |

Rate limits are enforced per key using a sliding 1-hour window stored in `api_rate_limits`. When exceeded, the API returns `HTTP 429`.

### Rotate keys periodically

Revoke and reissue keys on a schedule or whenever:
- A team member leaves
- A workstation or CI secret store may be compromised
- A key appears in logs, error messages, or source control

Revocation is instant. Reissuance takes 30 seconds.

### Audit `last_used_at`

Check for inactive keys regularly:

```bash
# Show keys not used in the last 30 days
sqlite3 maltriage.db "
SELECT key_id, label, datetime(last_used_at, 'unixepoch') as last_used
FROM api_keys
WHERE revoked = 0
  AND (last_used_at IS NULL OR last_used_at < strftime('%s','now','-30 days'))
ORDER BY last_used_at ASC
"
```

Revoke any keys that have not been used and are no longer needed.

### Store tokens securely

Never put a `mh_` token in:
- Source code or git repositories
- CI/CD environment variable names that appear in build logs
- Unencrypted config files

Prefer:
- OS secret store / keychain (1Password, macOS Keychain, Windows Credential Manager)
- CI/CD secret storage (GitHub Actions secrets, GitLab CI variables, Azure Key Vault)
- Environment variables injected at runtime, not baked into images

---

## Direct SQLite access (advanced)

All data lives in `maltriage.db` at the repo root. You can query or modify it directly with `sqlite3` if needed.

```bash
# Count active keys
sqlite3 maltriage.db "SELECT COUNT(*) FROM api_keys WHERE revoked = 0"

# Show all jobs for a specific key
sqlite3 maltriage.db "
SELECT job_id, status, datetime(created_at,'unixepoch') as created, sha256
FROM api_jobs
WHERE key_id = '227e520f-6020-498a-9954-c48c461b3a33'
ORDER BY created_at DESC
LIMIT 20
"

# Clear rate limit counters for a key (e.g. after an accidental burst)
sqlite3 maltriage.db "DELETE FROM api_rate_limits WHERE key_id = '227e520f-...'"
```
