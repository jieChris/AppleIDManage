import sqlite3
import unittest
import json
import threading
import urllib.request

from vault_api import VaultError, VaultHandler, VaultServer, VaultStore, backup_sqlite_database


def record(account="a@example.com", password="secret", updated_at="2026-08-12T00:00:00Z"):
    return {
        "id": account,
        "account": account,
        "password": password,
        "questions": ["q1", "q2", "q3"],
        "birthDate": "1984/2/25",
        "country": "美国",
        "updatedAt": updated_at,
    }


def group(group_id="group-1", name="常用", updated_at="2026-08-12T00:00:00Z"):
    return {"id": group_id, "name": name, "updatedAt": updated_at}


class VaultStoreTests(unittest.TestCase):
    def make_store(self):
        import tempfile

        self.temp_dir = tempfile.TemporaryDirectory()
        return VaultStore(f"{self.temp_dir.name}/vault.db", b"k" * 32)

    def tearDown(self):
        if hasattr(self, "temp_dir"):
            self.temp_dir.cleanup()

    def test_round_trip_is_encrypted_and_revisions_increment(self):
        store = self.make_store()

        result = store.sync([record()], {}, "")

        self.assertEqual(result["revision"], 1)
        self.assertEqual(result["records"][0]["password"], "secret")
        self.assertEqual(store.get_state()["records"][0]["password"], "secret")
        with open(f"{self.temp_dir.name}/vault.db", "rb") as database:
            self.assertNotIn(b"secret", database.read())


    def test_newer_record_wins_and_delete_watermark_blocks_old_snapshot(self):
        store = self.make_store()
        old = record(password="old")
        newer = record(password="new", updated_at="2026-08-12T00:02:00Z")

        store.sync([newer], {}, "")
        same_or_old = store.sync([old], {}, "")
        self.assertEqual(same_or_old["records"][0]["password"], "new")

        store.sync([], {"a@example.com": "2026-08-12T00:03:00Z"}, "")
        restored = store.sync([newer], {}, "")
        self.assertEqual(restored["records"], [])


    def test_clear_watermark_blocks_old_snapshot(self):
        store = self.make_store()
        old = record()
        store.sync([old], {}, "")

        cleared = store.clear()

        self.assertEqual(cleared["records"], [])
        self.assertEqual(store.sync([old], {}, "")["records"], [])


    def test_tampered_ciphertext_is_rejected(self):
        store = self.make_store()
        store.sync([], {}, "")

        with sqlite3.connect(f"{self.temp_dir.name}/vault.db") as connection:
            connection.execute("UPDATE vault_state SET ciphertext = zeroblob(length(ciphertext)) WHERE id = 1")

        with self.assertRaisesRegex(VaultError, "校验失败"):
            store.get_state()

    def test_sqlite_backup_uses_online_backup_without_key_access(self):
        store = self.make_store()
        store.sync([record()], {}, "")
        target = f"{self.temp_dir.name}/backup.db"

        backup_sqlite_database(f"{self.temp_dir.name}/vault.db", target)

        restored = VaultStore(target, b"k" * 32)
        self.assertEqual(restored.get_state()["records"][0]["account"], "a@example.com")

    def test_group_fields_round_trip_encrypted(self):
        store = self.make_store()
        grouped = {
            **record(),
            "secondaryEmail": "backup@example.com",
            "appPassword": "app-secret",
            "profileStatus": "complete",
            "groupId": "group-1",
            "groupOrder": 3,
            "isPrimary": True,
        }

        state = store.sync([grouped], {}, "", [group()], {}, 2)

        self.assertEqual(state["groups"][0]["name"], "常用")
        self.assertEqual(state["records"][0]["secondaryEmail"], "backup@example.com")
        self.assertEqual(state["records"][0]["appPassword"], "app-secret")
        self.assertEqual(state["records"][0]["profileStatus"], "complete")
        self.assertTrue(state["records"][0]["isPrimary"])
        with open(f"{self.temp_dir.name}/vault.db", "rb") as database:
            encrypted = database.read()
        self.assertNotIn(b"backup@example.com", encrypted)
        self.assertNotIn(b"app-secret", encrypted)

    def test_group_capacity_order_and_primary_are_normalized(self):
        store = self.make_store()
        records = []
        for index in range(7):
            records.append({
                **record(f"user{index}@example.com"),
                "groupId": "group-1",
                "groupOrder": 10 - index,
                "isPrimary": index in (0, 6),
            })

        state = store.sync(records, {}, "", [group()], {}, 2)
        members = [item for item in state["records"] if item["groupId"] == "group-1"]
        ungrouped = [item for item in state["records"] if not item["groupId"]]

        self.assertEqual(len(members), 6)
        self.assertEqual(sorted(item["groupOrder"] for item in members), list(range(6)))
        self.assertEqual(sum(item["isPrimary"] for item in members), 1)
        self.assertEqual(len(ungrouped), 1)
        self.assertFalse(ungrouped[0]["isPrimary"])

    def test_deleted_group_does_not_revive_and_clear_removes_groups(self):
        store = self.make_store()
        grouped = {**record(), "groupId": "group-1", "groupOrder": 0, "isPrimary": True}
        store.sync([grouped], {}, "", [group()], {}, 2)

        state = store.sync(
            [grouped],
            {},
            "",
            [group()],
            {"group-1": "2026-08-12T00:01:00Z"},
            2,
        )

        self.assertEqual(state["groups"], [])
        self.assertEqual(state["records"][0]["groupId"], "")
        self.assertFalse(state["records"][0]["isPrimary"])
        cleared = store.clear()
        self.assertEqual(cleared["groups"], [])
        self.assertEqual(cleared["deletedGroups"], {})
        restored = store.sync([grouped], {}, "", [group()], {}, 2)
        self.assertEqual(restored["records"], [])
        self.assertEqual(restored["groups"], [])

    def test_legacy_client_preserves_extended_fields(self):
        store = self.make_store()
        current = {
            **record(updated_at="2026-08-12T00:00:00Z"),
            "secondaryEmail": "backup@example.com",
            "appPassword": "app-secret",
            "profileStatus": "complete",
            "groupId": "group-1",
            "groupOrder": 0,
            "isPrimary": True,
        }
        store.sync([current], {}, "", [group()], {}, 2)
        legacy = record(password="new-password", updated_at="2026-08-12T00:02:00Z")

        state = store.sync([legacy], {}, "", [], {}, 1)
        updated = state["records"][0]

        self.assertEqual(updated["password"], "new-password")
        self.assertEqual(updated["secondaryEmail"], "backup@example.com")
        self.assertEqual(updated["appPassword"], "app-secret")
        self.assertEqual(updated["profileStatus"], "complete")
        self.assertEqual(updated["groupId"], "group-1")
        self.assertTrue(updated["isPrimary"])

    def test_legacy_payload_gets_safe_defaults(self):
        store = self.make_store()

        state = store.sync([record()], {}, "")
        normalized = state["records"][0]

        self.assertEqual(state["groups"], [])
        self.assertEqual(state["deletedGroups"], {})
        self.assertEqual(normalized["secondaryEmail"], "")
        self.assertEqual(normalized["appPassword"], "")
        self.assertEqual(normalized["profileStatus"], "complete")
        self.assertEqual(normalized["groupId"], "")
        self.assertEqual(normalized["groupOrder"], 0)
        self.assertFalse(normalized["isPrimary"])


class VaultApiTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.temp_dir = tempfile.TemporaryDirectory()
        self.server = VaultServer(
            ("127.0.0.1", 0),
            VaultHandler,
            VaultStore(f"{self.temp_dir.name}/vault.db", b"k" * 32),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())

    def test_state_sync_and_clear_routes(self):
        status, initial = self.request("GET", "/vault/state")
        self.assertEqual(status, 200)
        self.assertEqual(initial["revision"], 0)

        status, synced = self.request("POST", "/vault/sync", {
            "schemaVersion": 2,
            "records": [{**record(), "groupId": "group-1", "isPrimary": True}],
            "deleted": {},
            "clearAt": "",
            "groups": [group()],
            "deletedGroups": {},
        })
        self.assertEqual(status, 200)
        self.assertEqual(synced["records"][0]["account"], "a@example.com")
        self.assertEqual(synced["groups"][0]["id"], "group-1")
        self.assertTrue(synced["records"][0]["isPrimary"])

        status, cleared = self.request("POST", "/vault/clear")
        self.assertEqual(status, 200)
        self.assertEqual(cleared["records"], [])


if __name__ == "__main__":
    unittest.main()
