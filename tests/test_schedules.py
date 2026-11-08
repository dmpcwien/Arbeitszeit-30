"""Individuelle Dienstpläne, Prüfhilfen und rückwärtskompatible Migration."""
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import server as app


class ScheduleAndDeviationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.previous = (app.DATA_DIR, app.DB_PATH)
        app.DATA_DIR = Path(self.tmp.name)
        app.DB_PATH = app.DATA_DIR / "test.sqlite3"
        app.init_db()
        with app.conn() as db:
            app.create_user(db, None, "Test-Admin", "admin@example.invalid", "admin")
            app.create_user(db, None, "Test-Arbeit", "worker@example.invalid")

    def tearDown(self):
        app.DATA_DIR, app.DB_PATH = self.previous
        self.tmp.cleanup()

    @staticmethod
    def weekly():
        return [("09:00", "17:00"), ("09:00", "17:00"),
                ("09:00", "17:00"), ("09:00", "17:00"),
                ("09:00", "15:00"), ("", ""), ("", "")]

    @staticmethod
    def accounts(db):
        a = db.execute("SELECT * FROM users WHERE email='admin@example.invalid'").fetchone()
        w = db.execute("SELECT * FROM users WHERE email='worker@example.invalid'").fetchone()
        return a, w

    def test_plan_does_not_modify_existing_time_records(self):
        with app.conn() as db:
            admin, employee = self.accounts(db)
            db.execute("INSERT INTO shifts(user_id,started_at,ended_at) VALUES(?,?,?)",
                       (employee["id"], "2026-10-30T08:00:00+00:00",
                        "2026-10-30T16:00:00+00:00"))
            app.schedule_save(db, admin, employee["id"], self.weekly())
            self.assertEqual(len(app.scheduled_week(db, employee["id"])), 5)
            shift = db.execute("SELECT * FROM shifts WHERE user_id=?", (employee["id"],)).fetchone()
            self.assertEqual(shift["started_at"], "2026-10-30T08:00:00+00:00")
        app.init_db()
        with app.conn() as db:
            _, employee = self.accounts(db)
            self.assertEqual(len(app.scheduled_week(db, employee["id"])), 5)
            self.assertEqual(db.execute("SELECT count(*) FROM shifts").fetchone()[0], 1)

    def test_employees_cannot_change_plans_or_other_profiles(self):
        with app.conn() as db:
            admin, employee = self.accounts(db)
            with self.assertRaises(PermissionError):
                app.schedule_save(db, employee, admin["id"], self.weekly())
            self.assertEqual(len(app.scheduled_week(db, employee["id"])), 0)

    def test_overnight_plans_and_invalid_times(self):
        self.assertEqual(app.scheduled_duration("22:00", "06:00"), 480)
        with self.assertRaises(ValueError):
            app.scheduled_duration("08:00", "08:00")
        with self.assertRaises(ValueError):
            app.scheduled_duration("bad", "14:00")
        with app.conn() as db:
            admin, worker = self.accounts(db)
            week = self.weekly()
            week[0] = ("24:00", "09:00")
            with self.assertRaises(ValueError):
                app.schedule_save(db, admin, worker["id"], week)
            self.assertEqual(len(app.scheduled_week(db, worker["id"])), 0)

    def test_alerts_are_only_hints_not_mutations(self):
        with app.conn() as db:
            admin, employee = self.accounts(db)
            app.schedule_save(db, admin, employee["id"], self.weekly())
            monday = datetime(2026, 11, 9, 13, 30, tzinfo=app.VIENNA)
            flags = app.flags_for_user(db, employee["id"], monday)
            self.assertTrue(any("kein Arbeitsbeginn" in text for text in flags))
            self.assertIsNone(app.get_open_shift(db, employee["id"]))
            self.assertEqual(db.execute("SELECT count(*) FROM shifts").fetchone()[0], 0)

    def test_schedule_page_escapes_names(self):
        with app.conn() as db:
            admin, worker = self.accounts(db)
            page = app.schedule_page(db, admin, worker["id"], "csrf-demo")
            self.assertIn("Montag", page)
            self.assertIn("Geplanter Beginn", page)
            with self.assertRaises(PermissionError):
                app.schedule_page(db, worker, admin["id"], "csrf-demo")


if __name__ == "__main__":
    unittest.main()
