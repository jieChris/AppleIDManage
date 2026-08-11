# Shared Server Vault Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将账号档案从浏览器长期 `localStorage` 迁移到 Visa 服务器上的单一共享库，并让通过现有门禁的所有设备看到同一份加密数据。

**Architecture:** 新增一个 Python 内网服务，使用 SQLite 保存单行 AES-256-GCM 密文，同时复用现有取码代理；Nginx 在 Basic Auth 之后代理 `/api/vault/*`。前端启动时拉取服务器状态，首次把旧 `localStorage` 合并上传，之后每次写入成功后以服务器返回状态替换本地内存。

**Tech Stack:** 浏览器原生 JavaScript/HTML/CSS、Python 3.12、SQLite、`cryptography` 的 `AESGCM`、Docker、Nginx Basic Auth。

---

### Task 1: Add the encrypted vault store and API contract tests

**Files:**
- Create: `test_vault_api.py`
- Create: `vault_api.py`
- Reuse: `fetch_proxy.py`

- [ ] **Step 1: Write failing store tests**

```python
def test_round_trip_is_encrypted_and_revisions_increment():
    store = VaultStore(db_path, b"k" * 32)
    record = {"id": "1", "account": "a@example.com", "password": "secret", "updatedAt": "2026-08-12T00:00:00Z"}
    result = store.sync([record], {}, "")
    assert result["revision"] == 1
    assert store.get_state()["records"][0]["password"] == "secret"
    assert b"secret" not in db_path.read_bytes()

def test_delete_watermark_and_clear_watermark_reject_old_snapshots():
    store = VaultStore(db_path, b"k" * 32)
    old = {"id": "1", "account": "a@example.com", "password": "old", "updatedAt": "2026-08-12T00:00:00Z"}
    store.sync([old], {}, "")
    store.sync([], {"a@example.com": "2026-08-12T00:01:00Z"}, "")
    assert store.sync([old], {}, "")["records"] == []
    store.sync([old], {}, "")
    store.clear()
    assert store.sync([old], {}, "")["records"] == []

def test_tampered_ciphertext_is_rejected():
    store = VaultStore(db_path, b"k" * 32)
    store.sync([], {}, "")
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE vault_state SET ciphertext = zeroblob(length(ciphertext)) WHERE id = 1")
    with pytest.raises(VaultError, match="校验失败"):
        store.get_state()
```

- [ ] **Step 2: Run the tests and verify the expected missing-module failure**

Run: `python3 -m pytest -q test_vault_api.py`

Expected: FAIL because `vault_api.py` and `VaultStore` do not exist yet.

- [ ] **Step 3: Implement the minimal encrypted store**

Implement `VaultStore` with these fixed boundaries:

```python
class VaultStore:
    def __init__(self, db_path: Path, key: bytes): ...
    def get_state(self) -> dict: ...
    def sync(self, records: list, deleted: dict, clear_at: str) -> dict: ...
    def clear(self) -> dict: ...
```

Create the SQLite table `(id=1, revision, nonce, ciphertext, updated_at)`, encrypt the JSON payload `{records, deleted, clearAt}` with a fresh 12-byte nonce and `AESGCM(key)`, and use `BEGIN IMMEDIATE` for writes. Normalize timestamps to UTC, only accept records newer than the global/account deletion watermark, and keep the server record when timestamps are equal. Raise `VaultError` for malformed state, invalid key length, or AES-GCM authentication failure.

- [ ] **Step 4: Run the tests and keep the store green**

Run: `python3 -m pytest -q test_vault_api.py`

Expected: PASS for encryption, revision, merge, deletion/clear watermarks, and tamper detection.

- [ ] **Step 5: Add the HTTP API and proxy route tests**

Expose only these internal paths from `VaultHandler`: `GET /health`, `GET /vault/state`, `POST /vault/sync`, `POST /vault/clear`, and `GET /fetch`. Limit JSON request bodies to 4 MiB, return `Cache-Control: no-store`, suppress request logging, and return JSON `{revision, records, deleted, clearAt}`. Import `fetch_text` and `ProxyError` from `fetch_proxy.py` for the existing same-origin SMS proxy.

- [ ] **Step 6: Run the Python self-checks**

Run: `python3 -m pytest -q test_vault_api.py && python3 vault_api.py --self-test && python3 fetch_proxy.py --self-test`

Expected: all tests pass and both self-checks print an `ok` line.

- [ ] **Step 7: Commit the backend implementation**

```bash
git add vault_api.py test_vault_api.py
git commit -m "feat: add encrypted shared vault API"
```

### Task 2: Connect the browser to the server and preserve the existing UI

**Files:**
- Modify: `app.js`
- Modify: `index.html`
- Modify: `styles.css`

- [ ] **Step 1: Add server-state helpers and a write gate**

Add `requestVault`, `applyServerState`, `setSyncStatus`, `loadServerState`, and a serialized `syncSnapshot` queue. Keep `loadRecords`/`saveRecords` only for first-run migration recovery. Use `api/vault/<path>` relative URLs so `/appleid/` deployment prefixes continue to work. Set `state.canWrite = false` while loading or after a failed request; copies, password reveal, search, and filters remain available, while import, remark, delete, clear, and code refresh are blocked.

- [ ] **Step 2: Migrate legacy records only after a successful server read**

On startup, fetch `/api/vault/state`, apply it, and if the old storage key contains records, POST them to `/api/vault/sync` with `migrate: true`. Only remove `apple-id-vault-records` after that POST succeeds. If either request fails, retain the old local data in memory as read-only, show a sync error, and keep the key untouched.

- [ ] **Step 3: Route every mutation through the server**

Import sends the merged candidate list and keeps the textarea on failure. Remark changes update the in-memory record timestamp and debounce one `/sync` request. Delete sends an account deletion watermark, clear calls `/clear`, and SMS refresh sends the resulting code status through `/sync`. On success use the complete server response; on failure keep the visible state and switch the write gate off.

- [ ] **Step 4: Remove full-page-looking updates**

Keep the existing targeted `updatePasswordUI` and `updateCodeUI` paths, render the record list only after a successful state response, and add a top-bar “刷新同步” button that fetches the server without `window.location.reload()`. Update the local-only copy to explain the shared encrypted server library and protected same-origin proxy.

- [ ] **Step 5: Run parser and browser-side checks**

Run: `node app.js` and `node --check app.js`.

Expected: parser self-check prints `parser self-check: ok`; no syntax errors.

- [ ] **Step 6: Commit the browser integration**

```bash
git add app.js index.html styles.css
git commit -m "feat: sync vault records through server"
```

### Task 3: Package the service and configure deployment

**Files:**
- Create: `Dockerfile.vault-api`
- Create: `backup_vault.sh`
- Create: `backup_vault.cron`
- Modify: `nginx/appleid-vault.conf`

- [ ] **Step 1: Pin the API image and non-root runtime**

Base on `python:3.12.3-slim-bookworm`, install `cryptography==41.0.7`, copy `vault_api.py` and `fetch_proxy.py`, create UID/GID `10001`, and start as container root only long enough to read the root-only mounted key and drop to UID/GID `10001` before serving. Mount database read/write, key read-only, and backup directories explicitly; set the root filesystem read-only and expose no host port.

- [ ] **Step 2: Add root-only daily backup**

Run the API’s `--backup` command from `/etc/cron.d/appleid-vault` at 03:17 UTC. Use SQLite’s online backup API, copy the key beside it with mode `0600`, create one UTC date directory, and remove backup directories older than seven days. Keep the backup directory mode `0700`.

- [ ] **Step 3: Proxy the protected API without request-body logs**

Add Nginx `location ^~ /api/vault/` with `access_log off`, proxy it to `appleid-api:8080/vault/`, and also set `access_log off` on `/api/fetch-code`. Keep the existing Basic Auth at server scope and the current 12-second proxy timeouts.

- [ ] **Step 4: Validate configuration locally**

Run: `docker build -f Dockerfile.vault-api -t appleid-vault-api:20260812 .` when Docker is available, `nginx -t` in the deployment image, and `git diff --check`.

Expected: image builds, Nginx configuration validates, and no whitespace errors are reported.

- [ ] **Step 5: Commit deployment artifacts**

```bash
git add Dockerfile.vault-api backup_vault.sh backup_vault.cron nginx/appleid-vault.conf
git commit -m "ops: package shared vault deployment"
```

### Task 4: Deploy and verify A/B device synchronization

**Files:**
- Deploy the committed site and service files to `/root/appleid-vault/` on `visa`.
- Preserve existing `/root/appleid-vault/site`, Basic Auth file, and fetch-proxy behavior until health checks pass.

- [ ] **Step 1: Create protected server directories and generate the key once**

Create `/root/appleid-vault/data` and `/root/appleid-vault/backups` with mode `0700`, generate `/root/appleid-vault/secrets/vault.key` with 32 random bytes and mode `0600` only if it does not already exist, and never print the key.

- [ ] **Step 2: Build and start the API on the existing internal Docker network**

Build `appleid-vault-api:20260812`, start `appleid-api` on `edge-migrate-net` with aliases `appleid-api`, bind-mount the data/key/backups paths, use `--read-only`, and confirm `docker inspect` shows no `HostPort` mapping.

- [ ] **Step 3: Switch Nginx and frontend atomically enough for the protected site**

Back up the current site/configuration, install the new static files and Nginx config, run `nginx -t`, reload `appleid-vault`, and then remove the obsolete `appleid-fetch` container only after `/api/vault/state` and `/api/fetch-code` work through the protected hostname.

- [ ] **Step 4: Verify security and data behavior**

Check unauthenticated `/appleid/api/vault/state` returns `401`, authenticated state returns JSON, A-device legacy data migrates and removes the old key, a second isolated browser context sees the same record, a B-device remark/delete/clear is visible after A-device sync, and tampering with the SQLite ciphertext causes a server error rather than plaintext output. Confirm the database bytes do not contain the password, a dated backup exists, and the API container has no public port.

- [ ] **Step 5: Record any route deviation and final validation**

Run the existing parser/proxy checks, API tests, Nginx validation, and the Codex in-app browser regression. If deployment requires a conservative deviation, record it under the `Route Deviation` section of the execution notes before continuing.

---

## Self-review

- Spec coverage: encryption, shared state, migration, timestamps, deletion/clear watermarks, write blocking, SMS proxy, Basic Auth, no public API port, and seven-day backups are covered by Tasks 1–4.
- Placeholder scan: no TBD/TODO or unbounded “handle later” steps.
- Type consistency: API state uses `revision`, `records`, `deleted`, and `clearAt` consistently in backend and browser payloads.
- Route Deviation: none added by this plan; the same-origin fetch proxy remains the already-documented conservative fallback for non-CORS HTTP SMS endpoints.
