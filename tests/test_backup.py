"""SQLite-Backup, Integritätsprüfung und Wiederherstellung mit Testdaten."""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import backup


class BackupTests(unittest.TestCase):
    def test_backup_is_consistent_and_restorable(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "db.sqlite3"
            destination = Path(tmp) / "snapshots"
            with sqlite3.connect(source) as db:
                db.execute("CREATE TABLE bookings (id INTEGER PRIMARY KEY, hours INTEGER)")
                db.execute("INSERT INTO bookings(hours) VALUES (480)")
                db.execute("PRAGMA journal_mode=WAL")
            snapshot = backup.backup_once(source, destination, keep=3)
            self.assertTrue(snapshot.is_file())
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
            with sqlite3.connect(snapshot) as restored:
                self.assertEqual(restored.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(restored.execute("SELECT hours FROM bookings").fetchone()[0], 480)
            with sqlite3.connect(source) as original:
                original.execute("INSERT INTO bookings(hours) VALUES (300)")
            with sqlite3.connect(snapshot) as restored:
                self.assertEqual(restored.execute("SELECT COUNT(*) FROM bookings").fetchone()[0], 1)
            second = backup.backup_once(source, destination, keep=3)
            self.assertNotEqual(snapshot, second)
            with sqlite3.connect(second) as restored:
                self.assertEqual(restored.execute("SELECT COUNT(*) FROM bookings").fetchone()[0], 2)

    def test_missing_db_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                backup.backup_once(Path(tmp) / "missing.sqlite3", Path(tmp) / "backup")

    def test_invalid_retention_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "db.sqlite3"
            sqlite3.connect(source).close()
            with self.assertRaises(ValueError):
                backup.backup_once(source, Path(tmp) / "backup", keep=1)


if __name__ == "__main__":
    unittest.main()
