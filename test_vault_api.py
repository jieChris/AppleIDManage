import sqlite3
import unittest

from vault_api import VaultError, VaultStore


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


if __name__ == "__main__":
    unittest.main()
