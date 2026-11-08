"""Regressionstests für Kernfunktionen der Zeiterfassung.

Ausführen: python -m unittest discover -s tests -v
"""
import ipaddress
from datetime import datetime
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

    def test_duplicate_request_token_is_idempotent(self):
        with app.conn() as db:
            worker, _ = self.accounts(db)
            token = "fixed_unique_token_0001"
            self.assertTrue(app.punch_once(db, worker["id"], "start", token))
            self.assertFalse(app.punch_once(db, worker["id"], "start", token))
            count = db.execute("SELECT COUNT(*) FROM shifts WHERE user_id=?", (worker["id"],)).fetchone()[0]
            self.assertEqual(count, 1)
            with self.assertRaises(ValueError):
                app.punch_once(db, worker["id"], "stop", "bad")

    def test_calendar_is_private_and_team_filter_limits_rows(self):
        with app.conn() as db:
            worker, admin = self.accounts(db)
            db.execute("INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                       (worker["id"], "2026-11-04T08:00:00+00:00",
                        "2026-11-04T15:00:00+00:00"))
            cal = app.calendar_page(db, worker, "2026-11")
            self.assertIn("Mein Monatskalender", cal)
            self.assertIn("7:00 h", cal)
            self.assertNotIn("Admin", cal)
            app.punch(db, worker["id"], "start")
            working = app.team_status_page(db, admin, "working")
            self.assertIn("Mitarbeiter &lt;Test&gt;", working)
            self.assertNotIn("<td>Admin</td>", working)
            absent = app.team_status_page(db, admin, "absent")
            self.assertIn("<td>Admin</td>", absent)
            self.assertNotIn("Mitarbeiter &lt;Test&gt;", absent)

    def test_live_elapsed_clock_subtracts_break_and_stays_read_only(self):
        with app.conn() as db:
            worker, _ = self.accounts(db)
            cursor = db.execute(
                "INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                (worker["id"], "2026-11-08T08:00:00+00:00",
                 "2026-11-08T11:15:00+00:00"))
            db.execute("INSERT INTO breaks(shift_id,started_at,ended_at) VALUES(?,?,?)",
                       (cursor.lastrowid, "2026-11-08T09:00:00+00:00",
                        "2026-11-08T09:15:00+00:00"))
            shift = db.execute("SELECT * FROM shifts WHERE id=?", (cursor.lastrowid,)).fetchone()
            before = db.execute("SELECT COUNT(*) FROM shifts").fetchone()[0]
            self.assertEqual(app.shift_net_seconds(db, shift), 10800)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM shifts").fetchone()[0], before)

    def test_page_only_loads_same_origin_script_when_logged_in(self):
        with app.conn() as db:
            worker, _ = self.accounts(db)
            # First-login users are redirected to password change, so no dashboard JS.
            self.assertNotIn('src="/static/dashboard.js"',
                             app.layout("Test", "Hallo", worker, "csrf-value"))
            db.execute("UPDATE users SET must_change=0 WHERE id=?", (worker['id'],))
            worker = db.execute("SELECT * FROM users WHERE id=?", (worker['id'],)).fetchone()
            logged_in = app.layout("Test", "Hallo", worker, "csrf-value")
            self.assertIn('src="/static/dashboard.js"', logged_in)
            self.assertNotIn('src="/static/dashboard.js"', app.start_page())

    def test_weekly_target_calculation_is_not_payroll(self):
        with app.conn() as db:
            worker, _ = self.accounts(db)
            db.execute("UPDATE users SET weekly_target_minutes=? WHERE id=?",
                       (2400, worker["id"]))
            db.execute("INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                       (worker["id"], "2026-11-03T07:00:00+00:00",
                        "2026-11-03T15:00:00+00:00"))
            updated = db.execute("SELECT * FROM users WHERE id=?", (worker["id"],)).fetchone()
            actual, target, diff = app.weekly_summary(
                db, updated, datetime(2026, 11, 4, 12, tzinfo=app.VIENNA))
            self.assertEqual((actual, target, diff), (480, 2400, -1920))

    def test_totp_rfc_vector_and_wrong_code(self):
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")
        self.assertEqual(app.totp_code(secret, at_time=59), "287082")
        self.assertTrue(app.verify_totp(secret, "287082", at_time=59))
        self.assertFalse(app.verify_totp(secret, "000000", at_time=59))
        self.assertFalse(app.verify_totp(secret, "invalid", at_time=59))

    def test_migration_preserves_existing_hours(self):
        with app.conn() as db:
            worker, _ = self.accounts(db)
            db.execute("INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                       (worker["id"], "2026-01-07T08:00:00+00:00",
                        "2026-01-07T16:00:00+00:00"))
            count_before = db.execute("SELECT COUNT(*) FROM shifts").fetchone()[0]
        app.init_db()
        app.init_db()
        with app.conn() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM shifts").fetchone()[0], count_before)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            self.assertIn("weekly_target_minutes", columns)
            self.assertIn("mfa_secret", columns)
            self.assertIn("remote_until", columns)

    def test_correction_requires_separate_admin_approval_and_keeps_original(self):
        with app.conn() as db:
            worker, admin = self.accounts(db)
            cur = db.execute("INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                             (worker["id"], "2026-01-08T08:00:00+00:00",
                              "2026-01-08T16:00:00+00:00"))
            request_id = app.submit_correction(
                db, worker, cur.lastrowid, "2026-01-08T10:00",
                "2026-01-08T18:00", "Fehlende Zeitkorrektur")
            current = db.execute("SELECT * FROM shifts WHERE id=?", (cur.lastrowid,)).fetchone()
            self.assertEqual(current["started_at"], "2026-01-08T08:00:00+00:00")
            with self.assertRaises(PermissionError):
                app.review_correction(db, worker, request_id, "approved", "")
            app.review_correction(db, admin, request_id, "approved", "Geprüft")
            new = db.execute("SELECT * FROM shifts WHERE id=?", (cur.lastrowid,)).fetchone()
            self.assertNotEqual(new["started_at"], current["started_at"])
            status = db.execute("SELECT status,original_start,reviewed_by FROM correction_requests WHERE id=?",
                                (request_id,)).fetchone()
            self.assertEqual(status["status"], "approved")
            self.assertEqual(status["original_start"], current["started_at"])
            self.assertEqual(status["reviewed_by"], admin["id"])
            with self.assertRaises(ValueError):
                app.review_correction(db, admin, request_id, "approved", "Nochmal")

    def test_correction_rejection_keeps_shift_untouched(self):
        with app.conn() as db:
            worker, admin = self.accounts(db)
            cur = db.execute("INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                             (worker["id"], "2026-01-09T08:00:00+00:00",
                              "2026-01-09T16:00:00+00:00"))
            req = app.submit_correction(db, worker, cur.lastrowid,
                                        "2026-01-09T10:00", "2026-01-09T18:00",
                                        "Bitte Anfang ändern")
            with self.assertRaises(ValueError):
                app.review_correction(db, admin, req, "rejected", "")
            app.review_correction(db, admin, req, "rejected", "Nicht plausibel")
            shift = db.execute("SELECT * FROM shifts WHERE id=?", (cur.lastrowid,)).fetchone()
            self.assertEqual(shift["started_at"], "2026-01-09T08:00:00+00:00")

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
