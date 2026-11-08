"""Regressionstests für Kernfunktionen der Zeiterfassung.

Ausführen: python -m unittest discover -s tests -v
"""
import ipaddress
import tempfile
import unittest
from pathlib import Path

import server as app


class ArbeitszeitTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.old_data_dir, self.old_db_path = app.DATA_DIR, app.DB_PATH
        app.DATA_DIR = Path(self.tempdir.name)
        app.DB_PATH = app.DATA_DIR / "test.sqlite3"
        app.init_db()
        with app.conn() as db:
            app.create_user(db, None, "Mitarbeiter <Test>", "test@example.invalid")
            app.create_user(db, None, "Admin", "admin@example.invalid", "admin")

    def tearDown(self):
        app.DATA_DIR, app.DB_PATH = self.old_data_dir, self.old_db_path
        self.tempdir.cleanup()

    def accounts(self, db):
        worker = db.execute("SELECT * FROM users WHERE email=?", ("test@example.invalid",)).fetchone()
        admin = db.execute("SELECT * FROM users WHERE email=?", ("admin@example.invalid",)).fetchone()
        return worker, admin

    def test_punch_flow_and_no_duplicate_open_shift(self):
        with app.conn() as db:
            worker, _ = self.accounts(db)
            app.punch(db, worker["id"], "start")
            with self.assertRaises(ValueError):
                app.punch(db, worker["id"], "start")
            app.punch(db, worker["id"], "pause")
            with self.assertRaises(ValueError):
                app.punch(db, worker["id"], "pause")
            with self.assertRaises(ValueError):
                app.punch(db, worker["id"], "stop")
            app.punch(db, worker["id"], "resume")
            app.punch(db, worker["id"], "stop")
            self.assertIsNone(app.get_open_shift(db, worker["id"]))
            with self.assertRaises(ValueError):
                app.punch(db, worker["id"], "stop")

    def test_net_time_subtracts_breaks(self):
        with app.conn() as db:
            worker, _ = self.accounts(db)
            shift = db.execute(
                "INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                (worker["id"], "2026-11-08T08:00:00+00:00", "2026-11-08T16:00:00+00:00"),
            )
            db.execute(
                "INSERT INTO breaks(shift_id,started_at,ended_at) VALUES(?,?,?)",
                (shift.lastrowid, "2026-11-08T12:00:00+00:00", "2026-11-08T12:30:00+00:00"),
            )
            entry = db.execute("SELECT * FROM shifts WHERE id=?", (shift.lastrowid,)).fetchone()
            self.assertEqual(app.shift_minutes(db, entry), (450, 30))

    def test_team_status_is_admin_only_and_escapes_names(self):
        with app.conn() as db:
            worker, admin = self.accounts(db)
            app.punch(db, worker["id"], "start")
            page = app.team_status_page(db, admin)
            self.assertIn("Im Dienst", page)
            self.assertIn("Mitarbeiter &lt;Test&gt;", page)
            self.assertNotIn("Mitarbeiter <Test>", page)
            self.assertIn("Nicht eingestempelt", page)
            with self.assertRaises(PermissionError):
                app.team_status_page(db, worker)
            app.punch(db, worker["id"], "pause")
            page = app.team_status_page(db, admin)
            self.assertIn("In Pause seit", page)

    def test_spreadsheet_formula_injection_is_escaped(self):
        for unsafe in ("=SUM(1,1)", "+CMD", "-CMD", "@SUM(A1)", "  =A1", "\t=1"):
            with self.subTest(value=unsafe):
                self.assertEqual(app.csv_safe_cell(unsafe), "'" + unsafe)
        self.assertEqual(app.csv_safe_cell("Normaler Name"), "Normaler Name")
        self.assertEqual(app.csv_safe_cell(None), "")

    def test_network_restriction_defaults_to_explicit_ranges(self):
        original = app.UNI_NETWORKS
        try:
            app.UNI_NETWORKS = (ipaddress.ip_network("10.55.0.0/16"),)
            with app.conn() as db:
                worker, _ = self.accounts(db)
                self.assertTrue(app.allowed_from_network(worker, "10.55.1.20"))
                self.assertFalse(app.allowed_from_network(worker, "10.56.1.20"))
                self.assertFalse(app.allowed_from_network(None, "10.56.1.20"))
        finally:
            app.UNI_NETWORKS = original


if __name__ == "__main__":
    unittest.main()
