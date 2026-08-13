#!/usr/bin/env python3
"""Encrypted shared vault API and the existing same-origin SMS proxy."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fetch_proxy import ProxyError, fetch_text


HOST = "0.0.0.0"
PORT = 8080
SERVICE_UID = 10001
SERVICE_GID = 10001
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 5000
MAX_DELETED = 5000
MAX_GROUPS = 1000
MAX_GROUP_SIZE = 6
AAD = b"apple-id-vault-state-v1"
VALID_CODE_STATUSES = {"idle", "loading", "found", "empty", "blocked"}
VALID_PROFILE_STATUSES = {"complete", "incomplete"}
EXTENDED_RECORD_FIELDS = (
    "secondaryEmail",
    "appPassword",
    "profileStatus",
    "groupId",
    "groupOrder",
    "isPrimary",
)


class VaultError(Exception):
    pass


class RequestError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def canonical_timestamp(value: object, fallback: str = "") -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        return fallback
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def later_timestamp(first: str, second: str) -> str:
    first_time = parse_timestamp(first)
    second_time = parse_timestamp(second)
    if first_time is None:
        return second if second_time else ""
    if second_time is None:
        return first
    return second if second_time > first_time else first


def text(value: object, limit: int = 10000) -> str:
    if value is None:
        return ""
    return str(value)[:limit]


def clean(value: object, limit: int = 10000) -> str:
    return " ".join(text(value, limit).strip().split())


def normalize_code_url(value: object) -> str:
    source = clean(value, 4096)
    if not source:
        return ""
    try:
        target = urlsplit(source)
    except ValueError:
        return ""
    return source if target.scheme in {"http", "https"} and target.hostname else ""


def normalize_record(raw: object, fallback_time: str | None = None) -> dict | None:
    if not isinstance(raw, dict):
        return None
    account = clean(raw.get("account"), 320)
    if not account:
        return None
    questions = raw.get("questions") if isinstance(raw.get("questions"), list) else []
    status = raw.get("codeStatus") if raw.get("codeStatus") in VALID_CODE_STATUSES else "idle"
    timestamp = canonical_timestamp(raw.get("updatedAt"), fallback_time or now_iso())
    sms_code = text(raw.get("smsCode"), 6)
    if len(sms_code) != 6 or not sms_code.isdigit():
        sms_code = ""
    profile_status = raw.get("profileStatus")
    if profile_status not in VALID_PROFILE_STATUSES:
        core_values = [account, raw.get("password"), *questions[:3], raw.get("birthDate"), raw.get("country")]
        profile_status = "complete" if len(questions) >= 3 and all(clean(value) for value in core_values) else "incomplete"
    try:
        group_order = max(0, int(raw.get("groupOrder", 0)))
    except (TypeError, ValueError):
        group_order = 0

    return {
        "id": clean(raw.get("id"), 80) or str(uuid.uuid4()),
        "account": account,
        "password": text(raw.get("password"), 4096),
        "questions": [clean(questions[index] if index < len(questions) else "", 4096) for index in range(3)],
        "birthDate": clean(raw.get("birthDate"), 80),
        "country": clean(raw.get("country"), 160),
        "remark": clean(raw.get("remark"), 2000),
        "phone": clean(raw.get("phone"), 80),
        "codeUrl": normalize_code_url(raw.get("codeUrl")),
        "smsCode": sms_code,
        "codeStatus": status,
        "codeError": clean(raw.get("codeError"), 500),
        "codeCheckedAt": canonical_timestamp(raw.get("codeCheckedAt")),
        "secondaryEmail": clean(raw.get("secondaryEmail"), 320),
        "appPassword": text(raw.get("appPassword"), 4096),
        "profileStatus": profile_status,
        "groupId": clean(raw.get("groupId"), 80),
        "groupOrder": group_order,
        "isPrimary": raw.get("isPrimary") is True,
        "updatedAt": timestamp,
    }


def normalize_group(raw: object, fallback_time: str | None = None) -> dict | None:
    if not isinstance(raw, dict):
        return None
    group_id = clean(raw.get("id"), 80)
    name = clean(raw.get("name"), 160)
    if not group_id or not name:
        return None
    return {
        "id": group_id,
        "name": name,
        "updatedAt": canonical_timestamp(raw.get("updatedAt"), fallback_time or now_iso()),
    }


def normalize_deleted(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    result: dict[str, str] = {}
    for account, timestamp in list(raw.items())[:MAX_DELETED]:
        account_name = clean(account, 320)
        canonical = canonical_timestamp(timestamp)
        if account_name and canonical:
            result[account_name] = canonical
    return result


def normalize_deleted_groups(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    result: dict[str, str] = {}
    for group_id, timestamp in list(raw.items())[:MAX_GROUPS]:
        normalized_id = clean(group_id, 80)
        canonical = canonical_timestamp(timestamp)
        if normalized_id and canonical:
            result[normalized_id] = canonical
    return result


def blocked_by(record: dict, clear_at: str, deleted: dict[str, str]) -> bool:
    record_time = parse_timestamp(record["updatedAt"])
    if record_time is None:
        return True
    clear_time = parse_timestamp(clear_at)
    deleted_time = parse_timestamp(deleted.get(record["account"], ""))
    return bool(
        (clear_time and record_time <= clear_time)
        or (deleted_time and record_time <= deleted_time)
    )


def group_blocked_by(group: dict, clear_at: str, deleted_groups: dict[str, str]) -> bool:
    group_time = parse_timestamp(group["updatedAt"])
    clear_time = parse_timestamp(clear_at)
    deleted_time = parse_timestamp(deleted_groups.get(group["id"], ""))
    return bool(
        group_time is None
        or (clear_time and group_time <= clear_time)
        or (deleted_time and group_time <= deleted_time)
    )


def normalize_layout(records: list[dict], groups: list[dict]) -> list[dict]:
    group_ids = {group["id"] for group in groups}
    members: dict[str, list[dict]] = {group_id: [] for group_id in group_ids}
    for record in records:
        if record["groupId"] not in group_ids:
            record.update(groupId="", groupOrder=0, isPrimary=False)
            continue
        members[record["groupId"]].append(record)

    for group_records in members.values():
        group_records.sort(key=lambda record: (record["groupOrder"], record["account"]))
        primary_kept = False
        for index, record in enumerate(group_records):
            if index >= MAX_GROUP_SIZE:
                record.update(groupId="", groupOrder=0, isPrimary=False)
                continue
            record["groupOrder"] = index
            record["isPrimary"] = bool(record["isPrimary"] and not primary_kept)
            primary_kept = primary_kept or record["isPrimary"]
    return records


def normalize_payload(raw: object) -> dict:
    if not isinstance(raw, dict):
        raw = {}
    clear_at = canonical_timestamp(raw.get("clearAt"))
    deleted = normalize_deleted(raw.get("deleted"))
    deleted_groups = normalize_deleted_groups(raw.get("deletedGroups"))
    groups: list[dict] = []
    group_positions: dict[str, int] = {}
    for candidate in raw.get("groups", []) if isinstance(raw.get("groups"), list) else []:
        group = normalize_group(candidate)
        if not group or group_blocked_by(group, clear_at, deleted_groups):
            continue
        existing_index = group_positions.get(group["id"])
        if existing_index is None:
            group_positions[group["id"]] = len(groups)
            groups.append(group)
        elif parse_timestamp(group["updatedAt"]) > parse_timestamp(groups[existing_index]["updatedAt"]):
            groups[existing_index] = group
    records: list[dict] = []
    positions: dict[str, int] = {}
    for candidate in raw.get("records", []) if isinstance(raw.get("records"), list) else []:
        record = normalize_record(candidate)
        if not record or blocked_by(record, clear_at, deleted):
            continue
        existing_index = positions.get(record["account"])
        if existing_index is None:
            positions[record["account"]] = len(records)
            records.append(record)
            continue
        existing = records[existing_index]
        if parse_timestamp(record["updatedAt"]) > parse_timestamp(existing["updatedAt"]):
            records[existing_index] = record
    records = normalize_layout(records[:MAX_RECORDS], groups[:MAX_GROUPS])
    return {
        "records": records,
        "deleted": deleted,
        "clearAt": clear_at,
        "groups": groups[:MAX_GROUPS],
        "deletedGroups": deleted_groups,
    }


def merge_payload(current: dict, incoming: dict, schema_version: int = 1) -> dict:
    clear_at = later_timestamp(current.get("clearAt", ""), incoming.get("clearAt", ""))
    deleted = dict(current.get("deleted", {}))
    for account, timestamp in incoming.get("deleted", {}).items():
        deleted[account] = later_timestamp(deleted.get(account, ""), timestamp)
    deleted_groups = dict(current.get("deletedGroups", {}))
    for group_id, timestamp in incoming.get("deletedGroups", {}).items():
        deleted_groups[group_id] = later_timestamp(deleted_groups.get(group_id, ""), timestamp)

    groups: list[dict] = []
    group_positions: dict[str, int] = {}
    for source in (current.get("groups", []), incoming.get("groups", [])):
        for group in source:
            if group_blocked_by(group, clear_at, deleted_groups):
                continue
            existing_index = group_positions.get(group["id"])
            if existing_index is None:
                group_positions[group["id"]] = len(groups)
                groups.append(group)
            elif parse_timestamp(group["updatedAt"]) > parse_timestamp(groups[existing_index]["updatedAt"]):
                groups[existing_index] = group

    records: list[dict] = []
    positions: dict[str, int] = {}
    for source_index, source in enumerate((current.get("records", []), incoming.get("records", []))):
        for record in source:
            if blocked_by(record, clear_at, deleted):
                continue
            existing_index = positions.get(record["account"])
            if existing_index is None:
                positions[record["account"]] = len(records)
                records.append(record)
            elif parse_timestamp(record["updatedAt"]) > parse_timestamp(records[existing_index]["updatedAt"]):
                if schema_version < 2 and source_index == 1:
                    record = {**record, **{field: records[existing_index][field] for field in EXTENDED_RECORD_FIELDS}}
                records[existing_index] = record
    records = normalize_layout(records[:MAX_RECORDS], groups[:MAX_GROUPS])
    return {
        "records": records,
        "deleted": deleted,
        "clearAt": clear_at,
        "groups": groups[:MAX_GROUPS],
        "deletedGroups": deleted_groups,
    }


class VaultStore:
    def __init__(self, db_path: str | Path, key: bytes):
        if len(key) != 32:
            raise VaultError("加密密钥必须是 32 字节")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.key = key
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    revision INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _decode_row(self, row: sqlite3.Row | None) -> tuple[int, dict]:
        if row is None:
            return 0, normalize_payload({})
        try:
            plain = AESGCM(self.key).decrypt(bytes(row["nonce"]), bytes(row["ciphertext"]), AAD)
            payload = json.loads(plain.decode("utf-8"))
        except (InvalidTag, ValueError, TypeError, json.JSONDecodeError) as error:
            raise VaultError("共享库加密校验失败") from error
        return int(row["revision"]), normalize_payload(payload)

    def _read(self, connection: sqlite3.Connection) -> tuple[int, dict]:
        return self._decode_row(connection.execute("SELECT * FROM vault_state WHERE id = 1").fetchone())

    def _write(self, connection: sqlite3.Connection, revision: int, payload: dict) -> None:
        nonce = secrets.token_bytes(12)
        plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(self.key).encrypt(nonce, plain, AAD)
        connection.execute(
            """
            INSERT INTO vault_state (id, revision, nonce, ciphertext, updated_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                revision = excluded.revision,
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext,
                updated_at = excluded.updated_at
            """,
            (revision, nonce, ciphertext, now_iso()),
        )

    @staticmethod
    def _public(revision: int, payload: dict) -> dict:
        return {"revision": revision, **payload}

    def get_state(self) -> dict:
        with self._connect() as connection:
            revision, payload = self._read(connection)
        return self._public(revision, payload)

    def sync(
        self,
        records: list,
        deleted: dict,
        clear_at: str,
        groups: list | None = None,
        deleted_groups: dict | None = None,
        schema_version: int = 1,
    ) -> dict:
        incoming = normalize_payload({
            "records": records,
            "deleted": deleted,
            "clearAt": clear_at,
            "groups": groups or [],
            "deletedGroups": deleted_groups or {},
        })
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            revision, current = self._read(connection)
            merged = merge_payload(current, incoming, schema_version)
            revision += 1
            self._write(connection, revision, merged)
            connection.commit()
        return self._public(revision, merged)

    def clear(self) -> dict:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            revision, current = self._read(connection)
            clear_at = later_timestamp(current.get("clearAt", ""), now_iso())
            for record in current.get("records", []):
                clear_at = later_timestamp(clear_at, record["updatedAt"])
            for group in current.get("groups", []):
                clear_at = later_timestamp(clear_at, group["updatedAt"])
            payload = {
                "records": [],
                "deleted": current.get("deleted", {}),
                "clearAt": clear_at,
                "groups": [],
                "deletedGroups": {},
            }
            revision += 1
            self._write(connection, revision, payload)
            connection.commit()
        return self._public(revision, payload)


def load_key(path: str | Path) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise VaultError("服务器密钥文件长度不正确")
    return key


def backup_sqlite_database(db_path: str | Path, output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    if temporary.exists():
        temporary.unlink()
    with sqlite3.connect(db_path) as source, sqlite3.connect(temporary) as target:
        source.backup(target)
    temporary.replace(output)
    output.chmod(0o600)
    return output


class VaultServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, store: VaultStore):
        self.store = store
        super().__init__(address, handler)


class VaultHandler(BaseHTTPRequestHandler):
    server: VaultServer

    def log_message(self, _format, *_args):
        return

    def log_error(self, _format, *_args):
        return

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise RequestError("请求体格式无效") from error
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise RequestError("请求体过大", 413)
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RequestError("请求体不是有效 JSON") from error
        if not isinstance(payload, dict):
            raise RequestError("请求体格式无效")
        return payload

    def _handle_fetch(self) -> None:
        values = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("url", [])
        if len(values) != 1:
            self._send_text(400, "missing url")
            return
        try:
            body = fetch_text(values[0])
        except ProxyError as error:
            self._send_text(error.status, str(error))
            return
        self._send_text(200, body)

    def do_GET(self):  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        if path == "/health":
            self._send_json(200, {"ok": True})
        elif path == "/vault/state":
            try:
                self._send_json(200, self.server.store.get_state())
            except VaultError:
                self._send_json(500, {"error": "共享库读取失败"})
        elif path == "/fetch":
            self._handle_fetch()
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        if path == "/vault/clear":
            try:
                self._send_json(200, self.server.store.clear())
            except VaultError:
                self._send_json(500, {"error": "共享库写入失败"})
            return
        if path != "/vault/sync":
            self._send_json(404, {"error": "not found"})
            return
        try:
            payload = self._read_json()
            records = payload.get("records", [])
            deleted = payload.get("deleted", {})
            clear_at = payload.get("clearAt", "")
            groups = payload.get("groups", [])
            deleted_groups = payload.get("deletedGroups", {})
            schema_version = payload.get("schemaVersion", 1)
            if (
                not isinstance(records, list)
                or not isinstance(deleted, dict)
                or not isinstance(clear_at, str)
                or not isinstance(groups, list)
                or not isinstance(deleted_groups, dict)
                or not isinstance(schema_version, int)
            ):
                raise RequestError("请求体字段格式无效")
            self._send_json(200, self.server.store.sync(
                records,
                deleted,
                clear_at,
                groups,
                deleted_groups,
                schema_version,
            ))
        except RequestError as error:
            self._send_json(error.status, {"error": str(error)})
        except VaultError:
            self._send_json(500, {"error": "共享库写入失败"})


def drop_privileges() -> None:
    if os.geteuid() != 0:
        return
    os.setgroups([])
    os.setgid(SERVICE_GID)
    os.setuid(SERVICE_UID)


def serve(db_path: Path, key_path: Path) -> None:
    key = load_key(key_path)
    drop_privileges()
    store = VaultStore(db_path, key)
    server = VaultServer((HOST, PORT), VaultHandler, store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = VaultStore(Path(directory) / "vault.db", b"k" * 32)
        first = {"account": "a@example.com", "password": "secret", "updatedAt": "2026-08-12T00:00:00Z"}
        assert store.sync([first], {}, "")["records"][0]["account"] == "a@example.com"
        assert store.sync([first], {"a@example.com": "2026-08-12T00:01:00Z"}, "")["records"] == []
        assert b"secret" not in (Path(directory) / "vault.db").read_bytes()
    print("vault-api self-check: ok")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--backup-sqlite", action="store_true")
    parser.add_argument("--db", default=os.getenv("VAULT_DB", "/data/vault.db"))
    parser.add_argument("--key", default=os.getenv("VAULT_KEY", "/run/secrets/vault.key"))
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.backup_sqlite:
        if not args.output:
            parser.error("--backup-sqlite requires --output")
        print(backup_sqlite_database(args.db, args.output))
    else:
        serve(Path(args.db), Path(args.key))


if __name__ == "__main__":
    main()
