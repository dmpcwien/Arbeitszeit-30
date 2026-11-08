"""HTTP-Integrationstests mit drei getrennten Benutzerkonten.

Die Tests laufen ausschließlich mit temporärer SQLite-Datenbank und lokalem
HTTP-Server auf 127.0.0.1, ohne echte Mitarbeiterdaten oder Uni-Systeme.
"""
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import tempfile
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
            client, "/punch", {"csrf": self.csrf(email), "action": action}
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
