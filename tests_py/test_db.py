import tempfile
import unittest
from pathlib import Path

from db import SubdomainStore


class TestSubdomainStore(unittest.TestCase):
    def test_sqlite_cache_roundtrip_and_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SubdomainStore(db_path=Path(tmp) / "test.db")
            store.init_db()

            self.assertEqual(store.get_stats(), {"total_apexes": 0, "total_subdomains": 0})

            rows = [
                ("api.example.com", "2022-01-15"),
                ("dev.example.com", "2023-06-01"),
            ]
            store.save_results("example.com", rows)

            cached = store.get_cached("example.com")
            self.assertIsNotNone(cached)
            assert cached is not None
            self.assertTrue(cached.is_fresh)
            self.assertEqual(cached.rows, rows)
            self.assertEqual(store.get_stats(), {"total_apexes": 1, "total_subdomains": 2})

            store.save_results("empty.com", [])
            self.assertIsNone(store.get_cached("empty.com"))


if __name__ == "__main__":
    unittest.main()
