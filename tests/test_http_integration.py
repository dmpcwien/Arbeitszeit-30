"""HTTP-Integrationstests mit drei getrennten Benutzerkonten.

Die Tests laufen ausschließlich mit temporärer SQLite-Datenbank und lokalem
HTTP-Server auf 127.0.0.1, ohne echte Mitarbeiterdaten oder Uni-Systeme.
"""
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import tempfile
import secrets
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor,
    ProxyHandler,
    Request,
    build_opener,
)

import server as app


class MehrbenutzerHttpTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.old_data_dir, self.old_db_path = app.DATA_DIR, app.DB_PATH
        app.DATA_DIR = Path(self.tempdir.name)
        app.DB_PATH = app.DATA_DIR / "arbeitszeit-test.sqlite3"
        app.init_db()

        self.passwords = {}
        with app.conn() as db:
            for name, email, role in (
                ("Testperson A", "a@example.invalid", "employee"),
                ("Testperson B", "b@example.invalid", "employee"),
                ("Test-Admin", "admin@example.invalid", "admin"),
            ):
                self.passwords[email] = app.create_user(db, None, name, email, role)
                # Test accounts only: avoid first-login password-change redirect.
                db.execute("UPDATE users SET must_change=0 WHERE email=?", (email,))

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        app.DATA_DIR, app.DB_PATH = self.old_data_dir, self.old_db_path
        self.tempdir.cleanup()

    def new_client(self):
        return build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))

    def request(self, client, path, fields=None):
        data = None if fields is None else urlencode(fields).encode("utf-8")
        req = Request(
            "http://127.0.0.1:%d%s" % (self.port, path),
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with client.open(req, timeout=10) as response:
                return response.status, response.read().decode("utf-8-sig")
        except HTTPError as error:
            return error.code, error.read().decode("utf-8-sig")

    def login(self, email):
        client = self.new_client()
        status, page = self.request(
            client,
            "/login",
            {"email": email, "password": self.passwords[email]},
        )
        self.assertEqual(status, 200, page[:300])
        self.assertIn("Meine Stempeluhr", page)
        return client

    def csrf(self, email):
        with app.conn() as db:
            user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            session = db.execute(
                "SELECT csrf FROM sessions WHERE user_id=? ORDER BY expires_at DESC LIMIT 1",
                (user["id"],),
            ).fetchone()
            self.assertIsNotNone(session)
            return session["csrf"]

    def punch(self, client, email, action):
        status, page = self.request(
            client, "/punch", {"csrf": self.csrf(email), "action": action, "request_id": secrets.token_urlsafe(16)}
        )
        self.assertEqual(status, 200, page[:300])
        return page

    def test_three_accounts_have_separate_shifts_and_permissions(self):
        employee_a = self.login("a@example.invalid")
        employee_b = self.login("b@example.invalid")
        admin = self.login("admin@example.invalid")

        self.punch(employee_a, "a@example.invalid", "start")

        status, a_records = self.request(employee_a, "/records")
        self.assertEqual(status, 200)
        self.assertIn("Testperson A", a_records)
        self.assertNotIn("Testperson B", a_records)

        status, b_records = self.request(employee_b, "/records")
        self.assertEqual(status, 200)
        self.assertNotIn("Testperson A", b_records)
        self.assertIn("Keine Buchungen im gewählten Monat.", b_records)

        status, team = self.request(admin, "/team")
        self.assertEqual(status, 200)
        self.assertIn("Testperson A", team)
        self.assertIn("Testperson B", team)
        self.assertIn("Im Dienst", team)

        status, denied = self.request(employee_b, "/team")
        self.assertEqual(status, 404)
        self.assertNotIn("Testperson A", denied)

        self.punch(employee_a, "a@example.invalid", "pause")
        status, team = self.request(admin, "/team")
        self.assertEqual(status, 200)
        self.assertIn("In Pause seit", team)

        self.punch(employee_a, "a@example.invalid", "resume")
        self.punch(employee_a, "a@example.invalid", "stop")
        self.punch(employee_b, "b@example.invalid", "start")

        status, admin_records = self.request(admin, "/records")
        self.assertEqual(status, 200)
        self.assertIn("Testperson A", admin_records)
        self.assertIn("Testperson B", admin_records)

        status, b_export = self.request(employee_b, "/export")
        self.assertEqual(status, 200)
        self.assertNotIn("Testperson A", b_export)
        self.assertIn("Testperson B", b_export)

    def test_authenticated_timer_script_and_no_guest_access(self):
        user = self.login("a@example.invalid")
        status, script = self.request(user, "/static/dashboard.js")
        self.assertEqual(status, 200)
        self.assertIn("live-work-time", script)
        self.assertIn("visibilitychange", script)
        guest = self.new_client()
        status, body = self.request(guest, "/static/dashboard.js")
        self.assertEqual(status, 200)  # The redirect returns the login page.
        self.assertIn("Anmelden", body)
        self.assertNotIn("live-work-time", body)

    def test_retransmitted_clock_in_request_only_creates_one_shift(self):
        client = self.login("a@example.invalid")
        csrf = self.csrf("a@example.invalid")
        token = "persistent_request_key_123456"
        payload = {"csrf": csrf, "action": "start", "request_id": token}
        first_status, _ = self.request(client, "/punch", payload)
        second_status, _ = self.request(client, "/punch", payload)
        self.assertEqual((first_status, second_status), (200, 200))
        with app.conn() as db:
            uid = db.execute("SELECT id FROM users WHERE email='a@example.invalid'").fetchone()[0]
            count = db.execute("SELECT count(*) FROM shifts WHERE user_id=?", (uid,)).fetchone()[0]
            self.assertEqual(count, 1)

    def test_monthly_pdf_xlsx_downloads_do_not_expose_other_employees(self):
        import io
        from zipfile import ZipFile
        employee_a = self.login("a@example.invalid")
        employee_b = self.login("b@example.invalid")
        self.punch(employee_a, "a@example.invalid", "start")
        self.punch(employee_a, "a@example.invalid", "stop")
        self.punch(employee_b, "b@example.invalid", "start")
        self.punch(employee_b, "b@example.invalid", "stop")
        month = app.datetime.now(app.VIENNA).strftime("%Y-%m")
        address = "http://127.0.0.1:%d" % self.port
        with employee_a.open(address + "/export-xlsx?month=" + month, timeout=10) as res:
            self.assertEqual(res.status, 200)
            self.assertIn("spreadsheetml.sheet", res.headers["Content-Type"])
            data = res.read()
        with ZipFile(io.BytesIO(data)) as book:
            sheet = book.read("xl/worksheets/sheet1.xml").decode("utf-8")
            self.assertIn("Testperson A", sheet)
            self.assertNotIn("Testperson B", sheet)
        with employee_a.open(address + "/export-pdf?month=" + month, timeout=10) as res:
            self.assertEqual(res.status, 200)
            self.assertEqual(res.headers["Content-Type"], "application/pdf")
            self.assertTrue(res.read(5).startswith(b"%PDF-"))

    def test_schedule_edit_team_warning_and_live_visibility(self):
        admin_client = self.login("admin@example.invalid")
        worker_client = self.login("a@example.invalid")
        with app.conn() as db:
            worker = db.execute("SELECT * FROM users WHERE email='a@example.invalid'").fetchone()
            employee_id = worker["id"]
        payload = {"csrf": self.csrf("admin@example.invalid"),
                   "user_id": employee_id}
        for day in range(7):
            payload["start_" + str(day)] = ""
            payload["end_" + str(day)] = ""
        today = app.datetime.now(app.VIENNA)
        day = today.weekday()
        # Fixed valid schedule times, independent of the runner's local hour.
        began = "07:00"
        ends = "08:00"
        payload["start_" + str(day)] = began
        payload["end_" + str(day)] = ends
        status, page = self.request(admin_client, "/schedule", payload)
        self.assertEqual(status, 200)
        self.assertIn("Dienstzeiten:", page)
        status, page = self.request(admin_client, "/team")
        self.assertEqual(status, 200)
        self.assertIn("team-auto-refresh", page)
        status, page = self.request(worker_client, "/schedule?user_id=" + str(employee_id))
        self.assertEqual(status, 404)
        self.assertNotIn("Geplanter Beginn", page)

    def test_mfa_enrollment_and_second_factor_login(self):
        a = self.login("a@example.invalid")
        status, _ = self.request(a, "/mfa-start", {"csrf": self.csrf("a@example.invalid")})
        self.assertEqual(status, 200)
        with app.conn() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", ("a@example.invalid",)).fetchone()
            secret = user["mfa_pending_secret"]
            self.assertIsNotNone(secret)
            self.assertIsNone(user["mfa_secret"])
        status, _ = self.request(a, "/mfa-confirm",
                                 {"csrf": self.csrf("a@example.invalid"),
                                  "code": app.totp_code(secret)})
        self.assertEqual(status, 200)
        with app.conn() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", ("a@example.invalid",)).fetchone()
            self.assertEqual(user["mfa_secret"], secret)
            self.assertIsNone(user["mfa_pending_secret"])
        no_code = self.new_client()
        status, page = self.request(no_code, "/login",
                                    {"email": "a@example.invalid",
                                     "password": self.passwords["a@example.invalid"]})
        self.assertEqual(status, 401)
        self.assertIn("Anmeldung fehlgeschlagen", page)
        with_code = self.new_client()
        status, page = self.request(with_code, "/login",
                                    {"email": "a@example.invalid",
                                     "password": self.passwords["a@example.invalid"],
                                     "code": app.totp_code(secret)})
        self.assertEqual(status, 200)
        self.assertIn("Meine Stempeluhr", page)

    def test_admin_mfa_guard_when_required(self):
        previous = app.REQUIRE_ADMIN_MFA
        try:
            admin = self.login("admin@example.invalid")
            app.REQUIRE_ADMIN_MFA = True
            status, page = self.request(admin, "/admin")
            self.assertEqual(status, 200)
            self.assertIn("Für die Verwaltung ist MFA erforderlich", page)
            self.assertNotIn("Neuen Zugang erstellen", page)
            status, _ = self.request(admin, "/mfa-start",
                                     {"csrf": self.csrf("admin@example.invalid")})
            self.assertEqual(status, 200)
            with app.conn() as db:
                secret = db.execute("SELECT mfa_pending_secret FROM users WHERE email=?",
                                    ("admin@example.invalid",)).fetchone()[0]
            status, _ = self.request(admin, "/mfa-confirm",
                                     {"csrf": self.csrf("admin@example.invalid"),
                                      "code": app.totp_code(secret)})
            self.assertEqual(status, 200)
            status, page = self.request(admin, "/admin")
            self.assertEqual(status, 200)
            self.assertIn("Neuen Zugang erstellen", page)
        finally:
            app.REQUIRE_ADMIN_MFA = previous

    def test_csrf_is_required_and_deactivation_revokes_session(self):
        employee_a = self.login("a@example.invalid")
        admin = self.login("admin@example.invalid")

        status, _ = self.request(employee_a, "/punch", {"action": "start"})
        self.assertEqual(status, 403)
        with app.conn() as db:
            user = db.execute(
                "SELECT id FROM users WHERE email='a@example.invalid'"
            ).fetchone()
            self.assertIsNone(app.get_open_shift(db, user["id"]))
            employee_id = user["id"]

        status, _ = self.request(
            admin,
            "/toggle-user",
            {"csrf": self.csrf("admin@example.invalid"), "user_id": employee_id},
        )
        self.assertEqual(status, 200)

        status, page = self.request(employee_a, "/records")
        self.assertEqual(status, 200)  # Redirect lands on login page.
        self.assertIn("Anmelden", page)
        self.assertNotIn("Arbeitszeitübersicht", page)


if __name__ == "__main__":
    unittest.main()
