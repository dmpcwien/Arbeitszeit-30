#!/usr/bin/env python3
"""Ephemerer Mehrbenutzer-Testserver (NUR fiktive Daten, nur Loopback).

Start: python scripts/demo_server.py --port 8765
Öffnen: http://127.0.0.1:8765 in separaten Browserprofilen.
Für Smartphones im LAN ist zunächst ein vertrauenswürdiger HTTPS-Proxy nötig.
"""
import argparse
import sys
import tempfile
from pathlib import Path
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server as app  # noqa: E402


DEMO_USERS = [
    ("Test-Administrator", "test-admin@example.invalid", "admin"),
    ("Testperson A", "test-a@example.invalid", "employee"),
    ("Testperson B", "test-b@example.invalid", "employee"),
    ("Testperson C", "test-c@example.invalid", "employee"),
    ("Testperson D", "test-d@example.invalid", "employee"),
]


def seed_demo():
    """Create five accounts, never use real users and never write credentials to Git."""
    app.init_db()
    credentials = []
    with app.conn() as db:
        if db.execute("SELECT count(*) FROM users").fetchone()[0] != 0:
            raise RuntimeError("Testdatenbank enthält bereits Benutzer.")
        for name, email, role in DEMO_USERS:
            password = app.create_user(db, None, name, email, role)
            db.execute("UPDATE users SET must_change=0 WHERE email=?", (email,))
            credentials.append((name, email, password))
    return credentials


def main():
    parser = argparse.ArgumentParser(description="Arbeitszeit 30: lokaler Mehrbenutzer-Testserver")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port muss zwischen 1024 und 65535 liegen.")
    # Explicitly separate from existing app/user databases and service configs.
    with tempfile.TemporaryDirectory(prefix="az30-fiktiv-") as ephemeral:
        app.DATA_DIR = Path(ephemeral)
        app.DB_PATH = app.DATA_DIR / "demo.sqlite3"
        app.REQUIRE_ADMIN_MFA = False
        app.SECURE_COOKIES = False  # HTTP only on the loopback interface.
        app.UNI_NETWORKS = app.parse_cidrs("127.0.0.1/32,::1/128")
        app.TRUSTED_PROXY_NETWORKS = ()
        credentials = seed_demo()
        print("\nLOKALER TESTBETRIEB, keine echten Arbeitszeitdaten.", flush=True)
        print(f"URL: http://127.0.0.1:{args.port}", flush=True)
        print("Fiktive Testkonten. Passwörter erscheinen nur hier:", flush=True)
        for name, email, password in credentials:
            print(f"{name}: {email}  |  Passwort: {password}", flush=True)
        print("Browserprofile/Inkognito-Fenster für verschiedene Konten nutzen.")
        print("Mit Strg+C beenden: sämtliche temporären Testdaten werden gelöscht.")
        try:
            with ThreadingHTTPServer(("127.0.0.1", args.port), app.Handler) as srv:
                srv.daemon_threads = True
                srv.serve_forever()
        except KeyboardInterrupt:
            print("\nTestserver beendet.", flush=True)


if __name__ == "__main__":
    main()
