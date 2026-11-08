"""Verify local demo server creates only temporary fictitious accounts."""
from pathlib import Path
import tempfile
import unittest

import server as app
from scripts.demo_server import DEMO_USERS, seed_demo


class DemoServerTests(unittest.TestCase):
    def test_five_accounts_are_fictitious_and_not_reinitialized(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_dir, old_db = app.DATA_DIR, app.DB_PATH
            try:
                app.DATA_DIR = Path(tmp)
                app.DB_PATH = app.DATA_DIR / "demo-test.sqlite3"
                credentials = seed_demo()
                self.assertEqual(len(credentials), 5)
                self.assertTrue(all(email.endswith("@example.invalid")
                                    for _, email, _ in credentials))
                with app.conn() as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM users").fetchone()[0], 5)
                    self.assertEqual(db.execute("SELECT count(*) FROM shifts").fetchone()[0], 0)
                    self.assertEqual(db.execute("SELECT count(*) FROM users WHERE role='admin'").fetchone()[0], 1)
                with self.assertRaises(RuntimeError):
                    seed_demo()
            finally:
                app.DATA_DIR, app.DB_PATH = old_dir, old_db


if __name__ == "__main__":
    unittest.main()
