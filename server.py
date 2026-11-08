#!/usr/bin/env python3
"""Arbeitszeiterfassung für bis zu 30 Benutzer mit zugelassenen Netzwerkbereichen.

Für Internetbetrieb unbedingt hinter einem HTTPS-Reverse-Proxy mit gesetztem
APP_SECURE_COOKIES=1 betreiben. Kein versteckter Administratorzugang.
"""
import argparse
import base64
import calendar
import csv
import hashlib
import hmac
import html
import io
import ipaddress
import os
import re
import secrets
import struct
import sqlite3
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo

VIENNA = ZoneInfo('Europe/Vienna')
UTC = timezone.utc
DATA_DIR = Path(os.getenv('APP_DATA_DIR', Path(__file__).resolve().parent / 'data'))
DB_PATH = DATA_DIR / 'arbeitszeit.sqlite3'
SUPER_EMAIL = os.getenv('APP_SUPER_EMAIL', '').strip()
ADMIN_EMAIL = os.getenv('APP_ADMIN_EMAIL', '').strip()
ADMIN_NAME = os.getenv('APP_ADMIN_NAME', 'Administrator').strip()
CAPACITY = 30
SESSION_SECONDS = 12 * 3600
MAX_BODY = 16 * 1024
PASSWORD_ITERATIONS = 2 ** 14
SECURE_COOKIES = os.getenv('APP_SECURE_COOKIES') == '1'
REQUIRE_ADMIN_MFA = os.getenv('APP_REQUIRE_ADMIN_MFA') == '1'


def parse_cidrs(value):
    # Nur von der IT festgelegte CIDR-Netze. Keine Vermutung über Uni-Adressen.
    return tuple(ipaddress.ip_network(x.strip(), strict=False)
                 for x in value.split(',') if x.strip())


# Im lokalen Testbetrieb ist ausschließlich Loopback freigegeben.
# Für die Universität muss APP_UNI_CIDRS durch geprüfte Adressen ersetzt werden.
UNI_NETWORKS = parse_cidrs(os.getenv('APP_UNI_CIDRS', '127.0.0.1/32,::1/128'))
# Nur Reverse-Proxys in dieser expliziten Liste dürfen X-Real-IP liefern.
TRUSTED_PROXY_NETWORKS = parse_cidrs(os.getenv('APP_TRUSTED_PROXY_CIDRS', ''))


def in_networks(ip, networks):
    try:
        address = ipaddress.ip_address(ip)
        return any(address in net for net in networks)
    except ValueError:
        return False


def allowed_from_network(user, client_ip, now=None):
    # Sichere Standardeinstellung: nur der über APP_UNI_CIDRS bestätigte Zugang.
    if client_ip and in_networks(client_ip, UNI_NETWORKS):
        return True
    if not user:
        return False
    return bool(user['remote_until'] and user['remote_until'] > (now if now is not None else int(time.time())))


def grant_remote(db, actor, target_id, days, reason):
    if actor['role'] != 'superadmin':
        raise PermissionError('Nur die Superadministration darf Netzwerkfreigaben ändern.')
    if days not in (0, 1, 7, 30):
        raise ValueError('Bitte einen gültigen Zeitraum auswählen.')
    if len(reason.strip()) < 8 or len(reason.strip()) > 300:
        raise ValueError('Bitte eine nachvollziehbare Begründung eingeben (8–300 Zeichen).')
    target = db.execute('SELECT id,active,email FROM users WHERE id=?', (target_id,)).fetchone()
    if not target or not target['active']:
        raise ValueError('Es wurde kein aktives Konto gefunden.')
    until = int(time.time()) + days * 24 * 3600 if days else 0
    db.execute('UPDATE users SET remote_until=? WHERE id=?', (until, target_id))
    audit(db, actor['id'], 'remote_access_granted' if days else 'remote_access_revoked',
          f'user:{target_id}', f'{days} Tage | Grund: {reason.strip()}')
    return until


def esc(s):
    return html.escape(str(s if s is not None else ''), quote=True)


def utc_now():
    return datetime.now(UTC).isoformat(timespec='seconds')


def parse_dt(s):
    return datetime.fromisoformat(s)


def local(dt):
    return parse_dt(dt).astimezone(VIENNA).strftime('%d.%m.%Y %H:%M') if dt else '–'


def to_local_input(dt):
    return parse_dt(dt).astimezone(VIENNA).strftime('%Y-%m-%dT%H:%M') if dt else ''


def from_local_input(s):
    dt = datetime.strptime(s, '%Y-%m-%dT%H:%M').replace(tzinfo=VIENNA)
    # Ambiguous DST times resolve to fold=0; corrections must be reviewed.
    return dt.astimezone(UTC).isoformat(timespec='seconds')


def hash_password(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(pw.encode('utf-8'), salt=salt, n=PASSWORD_ITERATIONS, r=8, p=1)
    return f'scrypt:{salt.hex()}:{key.hex()}'


def verify_password(pw, encoded):
    try:
        method, salt, expected = encoded.split(':')
        if method != 'scrypt':
            return False
        actual = hash_password(pw, bytes.fromhex(salt)).split(':')[-1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


@contextmanager
def conn():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    try:
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        c.execute('PRAGMA journal_mode=WAL')
        c.execute('PRAGMA busy_timeout=10000')
        with c:
            yield c
    finally:
        c.close()


def init_db():
    with conn() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('employee','admin','superadmin')),
            active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
            must_change INTEGER NOT NULL DEFAULT 1 CHECK(must_change IN (0,1)),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS shifts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            started_at TEXT NOT NULL, ended_at TEXT,
            edited_at TEXT, edited_by INTEGER REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS breaks (
            id INTEGER PRIMARY KEY,
            shift_id INTEGER NOT NULL REFERENCES shifts(id),
            started_at TEXT NOT NULL, ended_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL, target TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY, identity TEXT NOT NULL, attempted_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS shifts_user_date ON shifts(user_id, started_at);
        CREATE INDEX IF NOT EXISTS audit_created ON audit(created_at);
        CREATE TABLE IF NOT EXISTS punch_requests (
            user_id INTEGER NOT NULL REFERENCES users(id),
            request_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id,request_id)
        );
        CREATE TABLE IF NOT EXISTS correction_requests (
            id INTEGER PRIMARY KEY,
            requester_id INTEGER NOT NULL REFERENCES users(id),
            shift_id INTEGER REFERENCES shifts(id),
            requested_start TEXT NOT NULL,
            requested_end TEXT NOT NULL,
            original_start TEXT, original_end TEXT,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','approved','rejected')),
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewed_by INTEGER REFERENCES users(id),
            reviewer_note TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS corrections_status_created
            ON correction_requests(status,created_at);
        ''')
        if 'remote_until' not in {r['name'] for r in db.execute('PRAGMA table_info(users)')}:
            db.execute('ALTER TABLE users ADD COLUMN remote_until INTEGER NOT NULL DEFAULT 0')
        user_columns = {r['name'] for r in db.execute('PRAGMA table_info(users)')}
        if 'weekly_target_minutes' not in user_columns:
            db.execute('ALTER TABLE users ADD COLUMN weekly_target_minutes INTEGER NOT NULL DEFAULT 0')
        if 'mfa_secret' not in user_columns:
            db.execute('ALTER TABLE users ADD COLUMN mfa_secret TEXT')
        if 'mfa_pending_secret' not in user_columns:
            db.execute('ALTER TABLE users ADD COLUMN mfa_pending_secret TEXT')


def audit(db, actor_id, action, target, note=''):
    db.execute('INSERT INTO audit(actor_id, action, target, note, created_at) VALUES(?,?,?,?,?)',
               (actor_id, action, str(target), note[:500], utc_now()))


def create_user(db, actor_id, name, email, role='employee'):
    email = email.strip().lower()
    name = name.strip()
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) or len(email) > 254:
        raise ValueError('Bitte eine gültige E-Mail-Adresse eingeben.')
    if not (2 <= len(name) <= 100):
        raise ValueError('Name muss zwischen 2 und 100 Zeichen lang sein.')
    if role not in ('employee', 'admin', 'superadmin'):
        raise ValueError('Ungültige Rolle.')
    if db.execute('SELECT count(*) FROM users WHERE active=1').fetchone()[0] >= CAPACITY:
        raise ValueError(f'Maximal {CAPACITY} aktive Konten sind erlaubt.')
    pw = secrets.token_urlsafe(16)
    cur = db.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                     (name, email, hash_password(pw), role, utc_now()))
    audit(db, actor_id, 'user_created', f'user:{cur.lastrowid}', f'Rolle: {role}, E-Mail: {email}')
    return pw


def get_open_shift(db, user_id):
    return db.execute('SELECT * FROM shifts WHERE user_id=? AND ended_at IS NULL ORDER BY id DESC LIMIT 1',
                      (user_id,)).fetchone()


def get_open_break(db, shift_id):
    return db.execute('SELECT * FROM breaks WHERE shift_id=? AND ended_at IS NULL ORDER BY id DESC LIMIT 1',
                      (shift_id,)).fetchone()


def punch(db, user_id, action):
    now = utc_now()
    shift = get_open_shift(db, user_id)
    if action == 'start':
        if shift:
            raise ValueError('Es läuft bereits eine Arbeitszeit.')
        cur = db.execute('INSERT INTO shifts(user_id,started_at) VALUES(?,?)', (user_id, now))
        audit(db, user_id, 'start', f'shift:{cur.lastrowid}')
    elif action == 'pause':
        if not shift or get_open_break(db, shift['id']):
            raise ValueError('Eine Pause kann jetzt nicht begonnen werden.')
        cur = db.execute('INSERT INTO breaks(shift_id,started_at) VALUES(?,?)', (shift['id'], now))
        audit(db, user_id, 'pause', f'shift:{shift["id"]}')
    elif action == 'resume':
        if not shift or not (brk := get_open_break(db, shift['id'])):
            raise ValueError('Es läuft derzeit keine Pause.')
        db.execute('UPDATE breaks SET ended_at=? WHERE id=?', (now, brk['id']))
        audit(db, user_id, 'resume', f'shift:{shift["id"]}')
    elif action == 'stop':
        if not shift:
            raise ValueError('Keine offene Arbeitszeit vorhanden.')
        if get_open_break(db, shift['id']):
            raise ValueError('Bitte zuerst die Pause beenden.')
        db.execute('UPDATE shifts SET ended_at=? WHERE id=?', (now, shift['id']))
        audit(db, user_id, 'stop', f'shift:{shift["id"]}')
    else:
        raise ValueError('Unbekannte Aktion.')



def punch_once(db, user_id, action, request_id):
    """Idempotent Stempelbuchung: Wiederholung derselben Anfrage ist ein No-op."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{15,100}', request_id or ''):
        raise ValueError('Buchungsformular ist abgelaufen. Bitte Seite neu laden.')
    db.execute('DELETE FROM punch_requests WHERE created_at<?',
               ((datetime.now(UTC)-timedelta(days=7)).isoformat(timespec='seconds'),))
    result = db.execute('INSERT OR IGNORE INTO punch_requests(user_id,request_id,created_at) '
                        'VALUES(?,?,?)', (user_id,request_id,utc_now()))
    if result.rowcount == 0:
        return False
    punch(db,user_id,action)
    return True


def shift_minutes(db, shift, now=None):
    now = now or utc_now()
    start = parse_dt(shift['started_at'])
    end = parse_dt(shift['ended_at'] or now)
    total = max(0, round((end - start).total_seconds() / 60))
    pause = 0
    for b in db.execute('SELECT * FROM breaks WHERE shift_id=?', (shift['id'],)):
        b_end = parse_dt(b['ended_at'] or shift['ended_at'] or now)
        pause += max(0, round((b_end - parse_dt(b['started_at'])).total_seconds() / 60))
    return max(0, total - pause), pause


def fmt_minutes(m):
    return f'{m // 60}:{m % 60:02d} h'



def validate_shift_correction(db, user_id, start, end, shift_id=None):
    """Validate submitted or approved corrections against current records."""
    a, b = parse_dt(start), parse_dt(end)
    if b <= a or (b - a).total_seconds() > 48 * 3600:
        raise ValueError('Zeitraum muss positiv und höchstens 48 Stunden lang sein.')
    if b > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError('Buchungen in der Zukunft sind nicht möglich.')
    if shift_id:
        sh = db.execute('SELECT * FROM shifts WHERE id=? AND user_id=?',
                        (shift_id, user_id)).fetchone()
        if not sh or not sh['ended_at']:
            raise ValueError('Nur abgeschlossene eigene Schichten können korrigiert werden.')
        for brk in db.execute('SELECT * FROM breaks WHERE shift_id=?', (shift_id,)):
            if not brk['ended_at'] or parse_dt(brk['started_at']) < a or parse_dt(brk['ended_at']) > b:
                raise ValueError('Eine vorhandene Pause liegt außerhalb des neuen Zeitraums.')
    for other in db.execute('SELECT * FROM shifts WHERE user_id=? AND id<>?',
                            (user_id, shift_id or -1)):
        other_end = parse_dt(other['ended_at'] or utc_now())
        if a < other_end and b > parse_dt(other['started_at']):
            raise ValueError('Die beantragte Zeit überschneidet eine andere Schicht.')


def submit_correction(db, actor, shift_id, start_text, end_text, reason):
    reason = reason.strip()
    if not 8 <= len(reason) <= 500:
        raise ValueError('Bitte eine Begründung mit 8 bis 500 Zeichen angeben.')
    start, end = from_local_input(start_text), from_local_input(end_text)
    shift = None
    if shift_id:
        shift = db.execute('SELECT * FROM shifts WHERE id=? AND user_id=?',
                           (shift_id, actor['id'])).fetchone()
        if not shift:
            raise ValueError('Eigene Buchung nicht gefunden.')
        duplicate = db.execute(
            "SELECT 1 FROM correction_requests WHERE shift_id=? AND status='pending'",
            (shift_id,)).fetchone()
        if duplicate:
            raise ValueError('Für diese Buchung besteht bereits ein offener Antrag.')
    validate_shift_correction(db, actor['id'], start, end, shift_id or None)
    if not shift_id and db.execute(
        "SELECT 1 FROM correction_requests WHERE requester_id=? AND shift_id IS NULL"
        " AND requested_start=? AND status='pending'", (actor['id'], start)
    ).fetchone():
        raise ValueError('Ein entsprechender Antrag ist bereits offen.')
    cur = db.execute(
        'INSERT INTO correction_requests(requester_id,shift_id,requested_start,'
        'requested_end,original_start,original_end,reason,created_at) '
        'VALUES(?,?,?,?,?,?,?,?)',
        (actor['id'], shift_id or None, start, end,
         shift['started_at'] if shift else None,
         shift['ended_at'] if shift else None, reason, utc_now()))
    audit(db, actor['id'], 'correction_requested', f'correction:{cur.lastrowid}',
          'Schichtkorrektur' if shift else 'Nachtrag eines Arbeitstags')
    return cur.lastrowid


def review_correction(db, actor, request_id, decision, reviewer_note):
    if actor['role'] == 'employee':
        raise PermissionError('Keine Berechtigung zur Freigabe.')
    if decision not in ('approved', 'rejected'):
        raise ValueError('Ungültige Entscheidung.')
    reviewer_note = reviewer_note.strip()
    if decision == 'rejected' and len(reviewer_note) < 5:
        raise ValueError('Für die Ablehnung eine Begründung angeben.')
    if len(reviewer_note) > 500:
        raise ValueError('Kommentar ist zu lang.')
    request = db.execute(
        'SELECT correction_requests.*, users.role AS requester_role '
        'FROM correction_requests JOIN users ON users.id=correction_requests.requester_id '
        'WHERE correction_requests.id=?', (request_id,)).fetchone()
    if not request or request['status'] != 'pending':
        raise ValueError('Antrag nicht gefunden oder bereits bearbeitet.')
    if actor['id'] == request['requester_id']:
        raise ValueError('Eigene Anträge dürfen nicht selbst freigegeben werden.')
    if request['requester_role'] == 'superadmin' and actor['role'] != 'superadmin':
        raise PermissionError('Keine Berechtigung für Superadministrator-Anträge.')
    # Status-Reservierung und Schichtänderung erfolgen in einer Transaktion.
    updated = db.execute(
        'UPDATE correction_requests SET status=?,reviewed_at=?,reviewed_by=?,'
        "reviewer_note=? WHERE id=? AND status='pending'",
        (decision, utc_now(), actor['id'], reviewer_note, request_id))
    if updated.rowcount != 1:
        raise ValueError('Der Antrag wurde zwischenzeitlich bearbeitet.')
    if decision == 'approved':
        sh = None
        if request['shift_id']:
            sh = db.execute('SELECT * FROM shifts WHERE id=? AND user_id=?',
                            (request['shift_id'], request['requester_id'])).fetchone()
            if not sh or sh['started_at'] != request['original_start'] or sh['ended_at'] != request['original_end']:
                raise ValueError('Die Ursprungsbuchung wurde verändert. Bitte neuen Antrag stellen.')
        validate_shift_correction(db, request['requester_id'], request['requested_start'],
                                  request['requested_end'], request['shift_id'])
        if sh:
            db.execute('UPDATE shifts SET started_at=?,ended_at=?,edited_at=?,edited_by=? '
                       'WHERE id=?', (request['requested_start'], request['requested_end'],
                                     utc_now(), actor['id'], sh['id']))
        else:
            db.execute('INSERT INTO shifts(user_id,started_at,ended_at,edited_at,edited_by) '
                       'VALUES(?,?,?,?,?)',
                       (request['requester_id'], request['requested_start'],
                        request['requested_end'], utc_now(), actor['id']))
    audit(db, actor['id'], 'correction_' + decision, f'correction:{request_id}',
          (request['reason'] + ' | ' + reviewer_note)[:500])


def corrections_page(db, user, csrf, selected_shift_id=0):
    shift = db.execute('SELECT * FROM shifts WHERE id=? AND user_id=? AND ended_at IS NOT NULL',
                       (selected_shift_id, user['id'])).fetchone()
    original_start = to_local_input(shift['started_at']) if shift else ''
    original_end = to_local_input(shift['ended_at']) if shift else ''
    shift_info = (f'<p>Korrektur für Buchung #{shift["id"]} · '
                  f'<a href="/corrections">Stattdessen neuen Arbeitstag nachtragen</a></p>'
                  if shift else '<p>Neuen, vergessenen Arbeitstag beantragen.</p>')
    form = (f'<section class="card"><h2>Korrektur beantragen</h2>{shift_info}'
            f'<form method="POST" action="/request-correction">{csrf_input(csrf)}'
            f'<input type="hidden" name="shift_id" value="{shift["id"] if shift else 0}">'
            f'<label>Beginn</label><input type="datetime-local" name="start" value="{esc(original_start)}" required>'
            f'<label>Ende</label><input type="datetime-local" name="end" value="{esc(original_end)}" required>'
            f'<label>Begründung</label><textarea name="reason" minlength="8" maxlength="500" required></textarea>'
            '<p><button>Antrag absenden</button></p></form></section>')
    my_rows = '<tr><th>Beantragt am</th><th>Zeitraum</th><th>Status</th><th>Begründung</th></tr>'
    statuses = {'pending': 'Offen', 'approved': 'Genehmigt', 'rejected': 'Abgelehnt'}
    for r in db.execute('SELECT * FROM correction_requests WHERE requester_id=? '
                        'ORDER BY id DESC LIMIT 100', (user['id'],)):
        my_rows += (f'<tr><td>{local(r["created_at"])}</td>'
                    f'<td>{local(r["requested_start"])} – {local(r["requested_end"])}</td>'
                    f'<td>{statuses.get(r["status"], "–")}</td>'
                    f'<td>{esc(r["reason"])}</td></tr>')
    review_section = ''
    if user['role'] != 'employee':
        queue = '<tr><th>Person</th><th>Zeitraum</th><th>Begründung</th><th>Entscheidung</th></tr>'
        pending = db.execute('SELECT c.*,u.name,u.role FROM correction_requests c '
                             'JOIN users u ON u.id=c.requester_id WHERE c.status=? '
                             'ORDER BY c.id ASC LIMIT 100', ('pending',)).fetchall()
        for req in pending:
            if req['requester_id'] == user['id']:
                continue
            if req['role'] == 'superadmin' and user['role'] != 'superadmin':
                continue
            controls = (f'<form method="POST" action="/review-correction">'
                        f'{csrf_input(csrf)}<input type="hidden" name="request_id" value="{req["id"]}">'
                        '<label>Kommentar (bei Ablehnung erforderlich)</label>'
                        '<input name="note" maxlength="500">'
                        '<div class="buttons"><button name="decision" value="approved">Genehmigen</button>'
                        '<button name="decision" value="rejected" class="danger">Ablehnen</button></div></form>')
            queue += (f'<tr><td>{esc(req["name"])}</td>'
                      f'<td>{local(req["requested_start"])} – {local(req["requested_end"])}</td>'
                      f'<td>{esc(req["reason"])}</td><td>{controls}</td></tr>')
        review_section = ('<section class="card"><h2>Offene Anträge prüfen</h2>'
                          f'<div class="tablewrap"><table class="table">{queue}</table></div></section>')
    return ('<h2>Zeiten korrigieren</h2>' + form +
            '<section class="card"><h2>Meine Anträge</h2>'
            f'<div class="tablewrap"><table class="table">{my_rows}</table></div></section>' +
            review_section)


def csv_safe_cell(value):
    """Protect exported text from spreadsheet formula execution."""
    text = str(value if value is not None else '')
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def team_status_page(db, user, status_filter='all'):
    """Show active punch states to administration, not a location/attendance claim."""
    if user['role'] == 'employee':
        raise PermissionError('Nur die Verwaltung darf den Teamstatus sehen.')
    members = db.execute(
        'SELECT id,name FROM users WHERE active=1 ORDER BY name'
    ).fetchall()
    if status_filter not in ('all', 'working', 'paused', 'absent'):
        status_filter = 'all'
    filter_options = ''.join(
        f'<option value="{value}" {"selected" if value==status_filter else ""}>{label}</option>'
        for value,label in [('all','Alle'),('working','Im Dienst'),
                            ('paused','In Pause'),('absent','Nicht eingestempelt')])
    rows = '<tr><th>Mitarbeiter</th><th>Status</th><th>Beginn</th><th>Netto bisher</th></tr>'
    working = paused = not_punched = 0
    for member in members:
        shift = get_open_shift(db, member['id'])
        if not shift:
            not_punched += 1
            status, started, minutes = 'Nicht eingestempelt', '–', '–'
        else:
            brk = get_open_break(db, shift['id'])
            if brk:
                paused += 1
                status = 'In Pause seit ' + local(brk['started_at'])
            else:
                working += 1
                status = 'Im Dienst'
            started = local(shift['started_at'])
            minutes = fmt_minutes(shift_minutes(db, shift)[0])
        row_state = 'absent' if not shift else ('paused' if brk else 'working')
        if status_filter != 'all' and row_state != status_filter:
            continue
        rows += (f'<tr><td>{esc(member["name"])}</td><td>{esc(status)}</td>'
                 f'<td>{esc(started)}</td><td>{esc(minutes)}</td></tr>')
    total = len(members)
    return (f'<h2>Teamstatus</h2><div class="grid">'
            f'<section class="card"><h2>Im Dienst</h2><div class="metric">{working}</div></section>'
            f'<section class="card"><h2>In Pause</h2><div class="metric">{paused}</div></section>'
            f'<section class="card"><h2>Nicht eingestempelt</h2><div class="metric">{not_punched}</div></section>'
            f'</div><section class="card"><div class="bar"><h2>Alle aktiven Konten ({total})</h2>'
            f'<a class="btn subtle" href="/team">Aktualisieren</a></div>'
            f'<form action="/team" method="GET" class="bar">'
            f'<label for="status-filter">Statusfilter</label><select id="status-filter" '
            f'name="status" style="max-width:240px">{filter_options}</select>'
            '<button>Filtern</button></form>'
            f'<p class="small muted">Stand: {esc(datetime.now(VIENNA).strftime("%d.%m.%Y %H:%M"))} Uhr. '
            f'Angezeigt wird der Buchungsstatus, keine Standort- oder Anwesenheitsprüfung.</p>'
            f'<div class="tablewrap"><table class="table">{rows}</table></div></section>')


CSS = '''
.calendar td{vertical-align:top;min-width:95px;white-space:normal;height:88px}.calendar .calhours{font-weight:750;margin:4px 0}.calendar .calempty{background:#f4f7fb}.calendar strong{font-size:15px}
.hero{border:1px solid #aac2e5;background:linear-gradient(120deg,#fff,#eaf2fc)}.state{font-size:21px;font-weight:750;margin:16px 0}.state.working{color:#146b47}.state.pause{color:#995c0f}.state.muted{color:#506278}.primary-actions{margin:18px 0}.punchbtn{min-height:54px;min-width:160px;font-size:17px}.card+.card{margin-top:18px}@media(max-width:640px){.primary-actions form{width:100%}.punchbtn{width:100%}}
:root{font-family:Inter,system-ui,-apple-system,'Segoe UI',sans-serif;color:#172335;background:#f4f7fb;color-scheme:light}*{box-sizing:border-box}body{margin:0}a{color:#1959b7;text-decoration:none}a:hover{text-decoration:underline}header{background:#10243c;color:white;padding:16px 24px;display:flex;align-items:center;justify-content:space-between;gap:15px;flex-wrap:wrap}header a{color:#dfeaf7}header h1{font-size:19px;margin:0}main{max-width:1100px;margin:28px auto;padding:0 16px 60px}.bar{display:flex;align-items:center;gap:16px;flex-wrap:wrap}.muted{color:#617083}.small{font-size:13px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:16px;margin:18px 0}.card{background:white;padding:22px;border-radius:14px;border:1px solid #e0e8f3;box-shadow:0 2px 10px #16283f09}.card h2{font-size:18px;margin:0 0 16px}.metric{font-size:36px;font-weight:700;letter-spacing:-1px}button,.btn{cursor:pointer;border:0;border-radius:9px;padding:12px 16px;font-size:15px;font-weight:650;background:#225fbc;color:white;display:inline-block;text-decoration:none}button:hover,.btn:hover{filter:brightness(.94);text-decoration:none}.subtle{background:#eaf0f7;color:#243852}.danger{background:#b93841;color:white}button:disabled{opacity:.55;cursor:not-allowed}form.inline{display:inline}label{display:block;font-size:14px;font-weight:650;margin:12px 0 6px}input,select,textarea{border-radius:9px;width:100%;padding:11px 12px;border:1px solid #bfcddd;font-size:15px;background:#fff;color:#172335}textarea{min-height:88px}.field{max-width:420px}.pill{display:inline-block;background:#e6efff;color:#2056a2;padding:6px 9px;border-radius:30px;font-size:12px;font-weight:650}.flash{padding:14px 16px;border-radius:10px;background:#e4f5ed;color:#155c37;margin:14px 0}.err{background:#ffe9eb;color:#9e1d2a}.tablewrap{overflow:auto}.table{width:100%;border-collapse:collapse;font-size:14px}.table th{text-align:left;color:#657385;font-size:12px;text-transform:uppercase;letter-spacing:.05em;padding:12px}.table td{padding:12px;border-top:1px solid #e7edf4;white-space:nowrap}.table tr:hover td{background:#f9fbfd}.buttons{display:flex;gap:8px;flex-wrap:wrap}.quiet{border:1px solid #cedaea;border-radius:10px;background:#f7fafc;padding:16px}.warn{background:#fff2d7;color:#784a00;padding:11px 14px;border-radius:9px}nav{display:flex;gap:15px;flex-wrap:wrap}nav a{font-size:14px}.badge{font-size:12px;color:#506278}.mobileTitle{display:none}@media(max-width:640px){header{padding:16px}main{margin:16px auto;padding:0 12px 40px}.card{padding:17px}button{min-height:46px}.buttons button{flex:1}.metric{font-size:30px}}
@media(prefers-color-scheme:dark){
:root{color:#e8effa;background:#111824;color-scheme:dark}
body{background:#111824;color:#e8effa}header{background:#09111e}
.card{background:#1b2737;border-color:#38465b;box-shadow:none}
.hero{background:linear-gradient(120deg,#1b2737,#1b334b);border-color:#43648c}
a{color:#8cbdff}.muted,.small.muted,.badge{color:#bbc7d8}
input,select,textarea{background:#152131;border-color:#65738a;color:#f1f5fb}
.table td{border-color:#364255}.table tr:hover td{background:#233348}
.table th{color:#c4cedc}.subtle{background:#33445c;color:#eff5ff}
.pill,.quiet{background:#304660;color:#eff5ff}.warn{background:#5a421c;color:#ffe6b5}
.flash{background:#254a3c;color:#d2f6e3}.flash.err{background:#653037;color:#ffe2e4}
.calendar .calempty{background:#182131}.state.working{color:#7be0b2}
.state.pause{color:#ffcc77}.state.muted{color:#c7d3e4}
}

'''



def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def totp_code(secret, at_time=None):
    """RFC 6238-compatible 6-digit TOTP, 30-second window, SHA-1."""
    at_time = int(time.time() if at_time is None else at_time)
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', at_time // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff
    return f'{number % 1000000:06d}'


def verify_totp(secret, code, at_time=None):
    if not secret or not re.fullmatch(r'\d{6}', str(code)):
        return False
    at_time = int(time.time() if at_time is None else at_time)
    try:
        return any(hmac.compare_digest(totp_code(secret, at_time + offset), str(code))
                   for offset in (-30, 0, 30))
    except (ValueError, TypeError, base64.binascii.Error):
        return False


def security_page(user, csrf):
    if user['mfa_secret']:
        state = ('<p class="flash">Zwei-Faktor-Anmeldung ist aktiviert.</p>'
                 '<p class="small muted">Bei jedem neuen Login ist ein sechsstelliger '
                 'Code aus der Authenticator-App erforderlich.</p>'
                 f'<form method="POST" action="/mfa-disable">{csrf_input(csrf)}'
                 '<label>Aktuelles Passwort</label>'
                 '<input name="password" type="password" autocomplete="current-password" required>'
                 '<label>Authenticator-Code</label>'
                 '<input name="code" inputmode="numeric" pattern="[0-9]{6}" '
                 'maxlength="6" autocomplete="one-time-code" required>'
                 '<p><button class="danger">Zwei-Faktor-Anmeldung deaktivieren</button></p></form>')
    elif user['mfa_pending_secret']:
        state = ('<p>Den folgenden Schlüssel in deiner Authenticator-App als '
                 'zeitbasierten sechsstelligen Code einrichten.</p>'
                 f'<p class="quiet"><code>{esc(user["mfa_pending_secret"])}</code></p>'
                 f'<form method="POST" action="/mfa-confirm">{csrf_input(csrf)}'
                 '<label>Sechsstelliger Bestätigungscode</label>'
                 '<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" '
                 'autocomplete="one-time-code" required>'
                 '<p><button>Aktivierung bestätigen</button></p></form>'
                 '<p class="small muted">Teile den geheimen Schlüssel mit niemandem. '
                 'Die Aktivierung erfolgt erst nach erfolgreicher Bestätigung.</p>')
    else:
        state = ('<p>Ein zusätzlicher Authenticator-Code erhöht den Schutz '
                 'deines Kontos.</p>'
                 f'<form method="POST" action="/mfa-start">{csrf_input(csrf)}'
                 '<p><button>Authenticator einrichten</button></p></form>')
    required = ('<p class="warn">Für die Verwaltung ist MFA erforderlich. '
                'Bitte zuerst einrichten.</p>'
                if REQUIRE_ADMIN_MFA and user['role'] != 'employee' and not user['mfa_secret']
                else '')
    return '<h2>Kontosicherheit</h2><section class="card">' + required + state + '</section>'


def csrf_input(csrf):
    return f'<input type="hidden" name="csrf" value="{esc(csrf)}">'


def layout(title, content, user=None, csrf='', notice='', error=''):
    menu = ''
    if user:
        role = {'employee':'Mitarbeiter','admin':'Administrator','superadmin':'Superadministrator'}[user['role']]
        menu = (f'<nav><a href="/">Stempeluhr</a><a href="/records">Zeiten</a>'
                + ('<a href="/team">Teamstatus</a><a href="/admin">Verwaltung</a><a href="/audit">Protokoll</a>' if user['role'] != 'employee' else '')
                + ('<a href="/access">Zugriffsfreigaben</a>' if user['role'] == 'superadmin' else '')
                + f'<a href="/calendar">Kalender</a><a href="/corrections">Korrekturen</a><a href="/security">Sicherheit</a><a href="/password">Passwort</a><form method="POST" action="/logout" class="inline">{csrf_input(csrf)}<button class="subtle" type="submit">Abmelden</button></form></nav>')
        menu = f'<div class="bar"><span class="small">{esc(user["name"])} · {role}</span>{menu}</div>'
    flash = ('<div class="flash">'+esc(notice)+'</div>' if notice else '') + ('<div class="flash err">'+esc(error)+'</div>' if error else '')
    return f'''<!doctype html><html lang="de"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#10243c"><title>{esc(title)} · Arbeitszeit 30</title><style>{CSS}</style></head><body><header><h1>◷ Arbeitszeit 30</h1>{menu}</header><main>{flash}{content}</main></body></html>'''


def start_page():
    return layout('Anmeldung', f'''<section class="card" style="max-width:430px;margin:64px auto"><h2>Anmelden</h2><p class="muted">Zeiterfassung für maximal {CAPACITY} Konten einschließlich Administration</p><form method="POST" action="/login"><label>E-Mail-Adresse</label><input type="email" name="email" autocomplete="username" required><label>Passwort</label><input type="password" name="password" autocomplete="current-password" required><label>Authenticator-Code (falls eingerichtet)</label><input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"><p><button type="submit">Anmelden</button></p></form><p class="small muted">Bei Zugangsproblemen bitte die zuständige Administration kontaktieren.</p></section>''')


def weekly_summary(db, user, today=None):
    today = today or datetime.now(VIENNA)
    monday = (today - timedelta(days=today.weekday())).date()
    week_end = monday + timedelta(days=7)
    week_minutes = 0
    for sh in db.execute('SELECT * FROM shifts WHERE user_id=?', (user['id'],)):
        shift_day = parse_dt(sh['started_at']).astimezone(VIENNA).date()
        if monday <= shift_day < week_end:
            week_minutes += shift_minutes(db, sh)[0]
    target = user['weekly_target_minutes']
    return week_minutes, target, week_minutes - target if target else None


def dashboard(db, user, csrf):
    sh = get_open_shift(db, user['id'])
    br = get_open_break(db, sh['id']) if sh else None
    if not sh:
        status, action, caption, variant = 'Nicht eingestempelt', 'start', 'Arbeitsbeginn', 'muted'
    elif br:
        status, action, caption, variant = 'In Pause seit ' + local(br['started_at']), 'resume', 'Pause beenden', 'pause'
    else:
        status, action, caption, variant = 'Im Dienst seit ' + local(sh['started_at']), 'pause', 'Pause starten', 'working'
    now = datetime.now(VIENNA)
    month = now.strftime('%Y-%m')
    rows = db.execute('SELECT * FROM shifts WHERE user_id=? ORDER BY started_at DESC LIMIT 7',
                      (user['id'],)).fetchall()
    monthly = [r for r in db.execute('SELECT * FROM shifts WHERE user_id=?', (user['id'],))
               if parse_dt(r['started_at']).astimezone(VIENNA).strftime('%Y-%m') == month]
    minutes = sum(shift_minutes(db, r)[0] for r in monthly)
    week_minutes, target, difference = weekly_summary(db, user, now)
    today_minutes = sum(shift_minutes(db, r)[0] for r in monthly
                        if parse_dt(r['started_at']).astimezone(VIENNA).date() == now.date())
    buttons = (f'<form method="POST" action="/punch" class="inline">{csrf_input(csrf)}'
               f'<input type="hidden" name="action" value="{action}">'
               f'<input type="hidden" name="request_id" value="{secrets.token_urlsafe(18)}">'
               f'<button class="punchbtn">{caption}</button></form>')
    if sh and not br:
        buttons += (f'<form method="POST" action="/punch" class="inline">{csrf_input(csrf)}'
                    '<input type="hidden" name="action" value="stop">'
                    f'<input type="hidden" name="request_id" value="{secrets.token_urlsafe(18)}">'
                    '<button class="danger punchbtn">Feierabend</button></form>')
    lines = '<tr><th>Beginn</th><th>Ende</th><th>Pause</th><th>Arbeitszeit</th></tr>'
    for r in rows:
        net, pause = shift_minutes(db, r)
        lines += (f'<tr><td>{local(r["started_at"])}</td><td>{local(r["ended_at"])}</td>'
                  f'<td>{fmt_minutes(pause)}</td><td>{fmt_minutes(net)}</td></tr>')
    warn = ('<p class="warn">Diese Schicht ist seit mehr als 20 Stunden offen. '
            'Bitte gegebenenfalls von der Verwaltung korrigieren lassen.</p>'
            if sh and (datetime.now(UTC)-parse_dt(sh['started_at'])).total_seconds() > 20*3600 else '')
    if sh:
        current_net, current_pause = shift_minutes(db, sh)
        if current_net >= 360 and current_pause < 30:
            warn += ('<p class="warn">Pausen prüfen: Es sind mehr als sechs Stunden '
                     'erfasst, aber weniger als 30 Minuten Pause dokumentiert. '
                     'Es erfolgt kein automatischer Abzug.</p>')
    open_requests = db.execute(
        "SELECT COUNT(*) FROM correction_requests WHERE requester_id=? AND status='pending'",
        (user['id'],)).fetchone()[0]
    pending_notice = (f'<p class="quiet">Du hast {open_requests} offene Korrekturanträge. '
                      '<a href="/corrections">Anträge ansehen</a></p>'
                      if open_requests else '')
    target_text = (f'<div class="small muted">Soll: {fmt_minutes(target)} · '
                   f'Differenz: {"+" if difference >= 0 else "−"}{fmt_minutes(abs(difference))}</div>'
                   if difference is not None else
                   '<div class="small muted">Sollzeit noch nicht von der Verwaltung eingerichtet.</div>')
    return (f'<h2>Meine Stempeluhr</h2>'
            f'<section class="card hero"><h2>Aktueller Status</h2><div class="state {variant}">{esc(status)}</div>'
            f'<p class="small muted">Buchungszeit laut Server · Zeitzone Europa/Wien</p>'
            f'<div class="buttons primary-actions">{buttons}</div>{warn}{pending_notice}'
            f'<p><a href="/corrections">Fehlende Buchung oder Korrektur beantragen</a></p></section>'
            f'<div class="grid"><section class="card"><h2>Heute</h2>'
            f'<div class="metric">{fmt_minutes(today_minutes)}</div></section>'
            f'<section class="card"><h2>Diese Woche (Ist)</h2>'
            f'<div class="metric">{fmt_minutes(week_minutes)}</div>{target_text}</section>'
            f'<section class="card"><h2>Monat {now.strftime("%m.%Y")}</h2>'
            f'<div class="metric">{fmt_minutes(minutes)}</div>'
            '<p class="small muted">Offene Schichten laufen mit; Starttag bestimmt die Zuordnung.</p>'
            '</section></div><section class="card"><h2>Letzte Buchungen</h2>'
            f'<div class="tablewrap"><table class="table">{lines}</table></div>'
            '<p><a href="/records">Alle Buchungen ansehen</a></p></section>')



def calendar_page(db, user, month):
    """Read-only calendar of a person's recorded shifts (by start date)."""
    if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', month):
        month = datetime.now(VIENNA).strftime('%Y-%m')
    year, number = map(int, month.split('-'))
    by_day = {}
    for shift in db.execute('SELECT * FROM shifts WHERE user_id=?', (user['id'],)):
        at = parse_dt(shift['started_at']).astimezone(VIENNA)
        if at.year == year and at.month == number:
            day = at.day
            net, pause = shift_minutes(db, shift)
            entry = by_day.setdefault(day, [0, 0, 0])
            entry[0] += net
            entry[1] += pause
            entry[2] += 1
    cells = '<tr>' + ''.join(f'<th>{name}</th>' for name in
                              ('Mo','Di','Mi','Do','Fr','Sa','So')) + '</tr>'
    for week in calendar.monthcalendar(year, number):
        cells += '<tr>'
        for day in week:
            if not day:
                cells += '<td class="calempty"></td>'
                continue
            data = by_day.get(day)
            if data:
                info = (f'<div class="calhours">{fmt_minutes(data[0])}</div>'
                        f'<div class="small muted">Pause {fmt_minutes(data[1])}</div>'
                        f'<div class="small muted">{data[2]} Buchung(en)</div>')
            else:
                info = '<div class="small muted">–</div>'
            cells += f'<td><strong>{day}</strong>{info}</td>'
        cells += '</tr>'
    return (f'<h2>Mein Monatskalender</h2><section class="card">'
            f'<form method="GET" action="/calendar" class="bar">'
            f'<label for="calmonth">Monat</label>'
            f'<input id="calmonth" type="month" name="month" value="{month}">'
            '<button>Monat anzeigen</button></form>'
            '<p class="small muted">Schichten werden dem Starttag zugeordnet. '
            'Ein leerer Tag ist kein Beweis für Abwesenheit oder Urlaub.</p>'
            f'<div class="tablewrap"><table class="table calendar">{cells}</table></div>'
            '<p><a href="/corrections">Fehlende Buchung beantragen</a></p></section>')


def allowed_records(db, user):
    if user['role'] == 'employee':
        return db.execute('SELECT shifts.*, users.name, users.role FROM shifts JOIN users ON users.id=shifts.user_id WHERE shifts.user_id=? ORDER BY shifts.started_at DESC', (user['id'],)).fetchall()
    return db.execute('SELECT shifts.*, users.name, users.role FROM shifts JOIN users ON users.id=shifts.user_id ORDER BY shifts.started_at DESC').fetchall()


def records_page(db, user, csrf, month):
    if not re.fullmatch(r'\d{4}-(0[1-9]|1[012])', month):
        month = datetime.now(VIENNA).strftime('%Y-%m')
    rows = [r for r in allowed_records(db,user) if parse_dt(r['started_at']).astimezone(VIENNA).strftime('%Y-%m') == month]
    lines = '<tr><th>Person</th><th>Beginn</th><th>Ende</th><th>Pause</th><th>Netto</th>'+('<th>Aktion</th>' if user['role'] != 'employee' else '')+'</tr>'
    totals = {}
    for r in rows:
        net,pause = shift_minutes(db,r)
        totals[r['name']] = totals.get(r['name'],0)+net
        action = f'<td><a href="/edit?id={r["id"]}">Direkt korrigieren</a></td>' if user['role'] != 'employee' and (user['role']=='superadmin' or r['role']!='superadmin') else ('<td>–</td>' if user['role']!='employee' else '')
        lines += f'<tr><td>{esc(r["name"])}'+(' · <a href="/corrections?shift_id='+str(r['id'])+'">Antrag</a>' if r['user_id']==user['id'] and r['ended_at'] else '')+f'</td><td>{local(r["started_at"])}</td><td>{local(r["ended_at"])}</td><td>{fmt_minutes(pause)}</td><td>{fmt_minutes(net)}</td>{action}</tr>'
    summary = ' · '.join(f'{esc(k)}: <b>{fmt_minutes(v)}</b>' for k,v in sorted(totals.items())) or 'Keine Buchungen im gewählten Monat.'
    return f'''<h2>Arbeitszeitübersicht</h2><div class="card"><form method="GET" action="/records" class="bar"><div><label for="month">Monat</label><input id="month" type="month" name="month" value="{month}"></div><button>Filtern</button> <a class="btn subtle" href="/export?month={month}">CSV exportieren</a></form><p>{summary}</p><div class="tablewrap"><table class="table">{lines}</table></div><p class="small muted">Buchungen über Mitternacht werden hier dem Startmonat zugerechnet. Pausen sind abgezogen. Das sind erfasste Zeiten, keine automatische rechtliche Überstundenabrechnung.</p></div>'''


def admin_page(db, user, csrf):
    users = db.execute('SELECT id,name,email,role,active,must_change,weekly_target_minutes FROM users ORDER BY CASE role WHEN "superadmin" THEN 0 WHEN "admin" THEN 1 ELSE 2 END,name').fetchall()
    count = sum(u['active'] for u in users)
    lines = '<tr><th>Name</th><th>E-Mail</th><th>Rolle</th><th>Status</th><th>Wochen-Soll</th><th>Aktion</th></tr>'
    for u in users:
        role = {'employee':'Mitarbeiter','admin':'Administrator','superadmin':'Superadministrator'}[u['role']]
        if user['role'] == 'superadmin' and u['role'] != 'superadmin' and u['id'] != user['id']:
            state = 'Deaktivieren' if u['active'] else 'Aktivieren'
            act = f'<form method="POST" action="/toggle-user" class="inline">{csrf_input(csrf)}<input type="hidden" name="user_id" value="{u["id"]}"><button class="subtle" name="action" value="toggle">{state}</button></form>'
        elif u['role']=='employee' and user['role']=='admin':
            state = 'Deaktivieren' if u['active'] else 'Aktivieren'
            act = f'<form method="POST" action="/toggle-user" class="inline">{csrf_input(csrf)}<input type="hidden" name="user_id" value="{u["id"]}"><button class="subtle">{state}</button></form>'
        else:
            act = '–'
        target = ('–' if u['weekly_target_minutes'] == 0 else fmt_minutes(u['weekly_target_minutes']))
        if user['role']=='superadmin' or u['role']!='superadmin':
            target = (f'<form method="POST" action="/set-target">{csrf_input(csrf)}'
                      f'<input type="hidden" name="user_id" value="{u["id"]}">'
                      f'<label>Stunden/Woche</label><input type="number" name="weekly_hours" '
                      f'min="0" max="60" step="0.25" value="{u["weekly_target_minutes"]/60:g}" required>'
                      '<button class="subtle">Speichern</button></form>')
        lines += f'<tr><td>{esc(u["name"])}</td><td>{esc(u["email"])}</td><td>{role}</td><td>{"Aktiv" if u["active"] else "Inaktiv"}</td><td>{target}</td><td>{act}</td></tr>'
    roles = '<option value="employee">Mitarbeiter</option>' + ('<option value="admin">Administrator</option>' if user['role']=='superadmin' else '')
    return f'''<h2>Verwaltung</h2><div class="grid"><section class="card"><h2>Benutzerkonten</h2><div class="metric">{count} / {CAPACITY}</div><p class="small muted">Aktive Konten einschließlich Verwaltung</p><a href="/records">Stundenübersicht öffnen →</a><p><a href="/team">Aktuellen Teamstatus ansehen →</a></p></section><section class="card"><h2>Neuen Zugang erstellen</h2><form method="POST" action="/create-user">{csrf_input(csrf)}<label>Name</label><input name="name" maxlength="100" required><label>E-Mail</label><input name="email" type="email" required><label>Rolle</label><select name="role">{roles}</select><p><button>Konto erstellen</button></p><p class="small muted">Das einmalige Startpasswort wird auf der nächsten Seite angezeigt.</p></form></section></div><section class="card"><h2>Konten und Berechtigungen</h2><div class="tablewrap"><table class="table">{lines}</table></div><p class="small muted">Administratoren dürfen keine Superadministrator-Konten verändern. Berechtigungen und Korrekturen werden protokolliert.</p></section>'''



def access_page(db, user, csrf):
    if user['role'] != 'superadmin':
        raise PermissionError('Zugriff verweigert')
    users = db.execute('SELECT id,name,email,role,active,remote_until FROM users WHERE active=1 ORDER BY name').fetchall()
    lines = '<tr><th>Mitarbeiter</th><th>Netzzugriff</th><th>Freigabe ändern</th></tr>'
    now = int(time.time())
    for target in users:
        active_remote = bool(target['remote_until'] and target['remote_until'] > now)
        status = ('Extern bis ' + datetime.fromtimestamp(target['remote_until'], VIENNA).strftime('%d.%m.%Y %H:%M')
                  if active_remote else 'Nur Uni-Netz')
        form = (f'<form method="POST" action="/access" style="min-width:220px">{csrf_input(csrf)}'
                f'<input type="hidden" name="user_id" value="{target["id"]}">'
                '<label>Zeitraum</label><select name="days">'
                '<option value="0">Nur Uni-Netz (extern sperren)</option>'
                '<option value="1">Extern für 1 Tag</option>'
                '<option value="7">Extern für 7 Tage</option>'
                '<option value="30">Extern für 30 Tage</option></select>'
                '<label>Begründung</label><input name="reason" maxlength="300" minlength="8" required>'
                '<p><button class="subtle">Zugriff speichern</button></p></form>')
        lines += f'<tr><td>{esc(target["name"])}<p class="small muted">{esc(target["email"])}</p></td><td>{esc(status)}</td><td>{form}</td></tr>'
    return ('''<h2>Zugriffsfreigaben</h2><section class="card"><p class="warn">Standard: nur geprüfte Uni-Netze. Externe Freigaben gelten für das Benutzerkonto auch auf PCs und Smartphones, nicht für ein bestimmtes Smartphone. Alle Änderungen werden im Audit-Protokoll erfasst und sind für die autorisierte IT nachvollziehbar.</p><p class="small muted">Die Universität muss die IP-Netze, den Reverse-Proxy und Remote-Zugriff autorisieren. Eine externe Ausnahme ersetzt weder VPN noch Geräteprüfung/MFA.</p><div class="tablewrap"><table class="table">'''+lines+'''</table></div></section>''')


def edit_page(db, user, csrf, sh):
    br = db.execute('SELECT * FROM breaks WHERE shift_id=? ORDER BY id LIMIT 1', (sh['id'],)).fetchone()
    extra = db.execute('SELECT count(*) FROM breaks WHERE shift_id=?', (sh['id'],)).fetchone()[0]>1
    msg = '<p class="warn">Mehrere Pausen vorhanden. Um Fehleingaben zu vermeiden, können hier nur Beginn und Ende geändert werden; Pausen bleiben unverändert.</p>' if extra else ''
    owner = db.execute('SELECT name FROM users WHERE id=?',(sh['user_id'],)).fetchone()['name']
    return f'''<h2>Schicht #{sh['id']} korrigieren</h2><section class="card" style="max-width:640px"><p>Person: <b>{esc(owner)}</b></p>{msg}<form method="POST" action="/edit">{csrf_input(csrf)}<input type="hidden" name="shift_id" value="{sh['id']}"><label>Arbeitsbeginn</label><input type="datetime-local" name="start" value="{to_local_input(sh['started_at'])}" required><label>Arbeitsende</label><input type="datetime-local" name="end" value="{to_local_input(sh['ended_at'])}" required><label>Begründung (wird protokolliert)</label><textarea name="reason" required minlength="5" maxlength="500" placeholder="z. B. vergessen auszustempeln"></textarea><p><button>Änderung speichern</button> <a class="btn subtle" href="/records">Abbrechen</a></p></form></section>'''


def audit_page(db):
    lines='<tr><th>Zeitpunkt</th><th>Person</th><th>Aktion</th><th>Objekt</th><th>Details</th></tr>'
    for r in db.execute('SELECT audit.*,users.name FROM audit LEFT JOIN users ON users.id=audit.actor_id ORDER BY audit.id DESC LIMIT 300'):
        lines+=f'<tr><td>{local(r["created_at"])}</td><td>{esc(r["name"] or "System")}</td><td>{esc(r["action"])}</td><td>{esc(r["target"])}</td><td>{esc(r["note"])}</td></tr>'
    return f'<h2>Änderungsprotokoll</h2><section class="card"><div class="tablewrap"><table class="table">{lines}</table></div></section>'


class Handler(BaseHTTPRequestHandler):
    server_version='Arbeitszeit30/1.7'
    sys_version=''

    def log_message(self, format, *args):
        # Keine URL- oder Cookie-Protokollierung in der Standardausgabe.
        sys.stderr.write('%s %s\n' % (self.log_date_time_string(), format % args))

    def headers(self, status=200, content_type='text/html; charset=utf-8', extra=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if SECURE_COOKIES:
            self.send_header('Strict-Transport-Security','max-age=31536000')
        for k,v in (extra or []):
            self.send_header(k,v)
        self.end_headers()

    def send_html(self, body, status=200, extra=None):
        data=body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if SECURE_COOKIES:
            self.send_header('Strict-Transport-Security','max-age=31536000')
        for k,v in (extra or []):
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, target='/', cookie=None):
        extras=[('Location',target)]
        if cookie is not None:
            extras.append(('Set-Cookie',cookie))
        self.send_html('',303,extras)

    def parse_cookie(self):
        c = SimpleCookie()
        try:
            c.load(self.headers.get('Cookie',''))
            return c['az_session'].value if 'az_session' in c else None
        except Exception:
            return None

    def context(self, db):
        token=self.parse_cookie()
        if not token or len(token)>200:
            return None,None
        token_hash=hashlib.sha256(token.encode()).hexdigest()
        r=db.execute('SELECT users.*,sessions.csrf,sessions.expires_at FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=?',(token_hash,)).fetchone()
        if r and r['active'] and r['expires_at']>int(time.time()):
            return r,token_hash
        return None,None

    def get_form(self):
        try:
            n=int(self.headers.get('Content-Length','0'))
        except ValueError:
            raise ValueError('Ungültige Anfrage.')
        if n<0 or n>MAX_BODY:
            raise ValueError('Anfrage zu groß.')
        data=self.rfile.read(n)
        return {k:v[-1] for k,v in urllib.parse.parse_qs(data.decode('utf-8'),keep_blank_values=True).items()}

    def same_origin(self):
        origin=self.headers.get('Origin')
        if origin:
            target=urllib.parse.urlparse(origin)
            return target.netloc.lower() == self.headers.get('Host','').lower() and target.scheme in ('http','https')
        # Bei Browsern ohne Origin zusätzlich Referer kontrollieren, wenn vorhanden.
        referer=self.headers.get('Referer')
        if referer:
            return urllib.parse.urlparse(referer).netloc.lower()==self.headers.get('Host','').lower()
        return True

    def request_client_ip(self):
        peer = self.client_address[0]
        if in_networks(peer, TRUSTED_PROXY_NETWORKS):
            # Der Proxy MUSS X-Real-IP bei jeder Anfrage überschreiben;
            # kein Header oder mehrere Werte: Zugriff verweigern.
            raw = self.headers.get('X-Real-IP', '')
            if raw != raw.strip() or ',' in raw:
                return None
            try:
                return str(ipaddress.ip_address(raw))
            except ValueError:
                return None
        # Weitergeleitete Header von nicht vertrauenswürdigen Clients ignorieren.
        return peer

    def network_allowed(self, user):
        return allowed_from_network(user, self.request_client_ip())

    def do_GET(self):
        path=urllib.parse.urlsplit(self.path).path
        params=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        with conn() as db:
            user,token_hash=self.context(db)
            if not user:
                if path=='/login' or path=='/':
                    self.send_html(start_page());return
                self.redirect('/login');return
            if not self.network_allowed(user):
                self.send_html(layout('Zugriff verweigert','Zugriff aus diesem Netz für dieses Konto nicht freigegeben.'),403);return
            if user['must_change'] and path!='/password':
                self.redirect('/password');return
            if REQUIRE_ADMIN_MFA and user['role']!='employee' and not user['mfa_secret'] and path not in ('/security','/password'):
                self.redirect('/security');return
            csrf=user['csrf']
            if path=='/security':
                self.send_html(layout('Kontosicherheit',security_page(user,csrf),user,csrf));return
            if path=='/':
                content=dashboard(db,user,csrf)
                self.send_html(layout('Stempeluhr',content,user,csrf));return
            if path=='/calendar':
                month=params.get('month',[datetime.now(VIENNA).strftime('%Y-%m')])[0]
                self.send_html(layout('Kalender',calendar_page(db,user,month),user,csrf));return
            if path=='/corrections':
                try: selected=int(params.get('shift_id',[0])[0])
                except (ValueError,TypeError): selected=0
                self.send_html(layout('Korrekturen',
                                      corrections_page(db,user,csrf,selected),user,csrf));return
            if path=='/records':
                month=params.get('month',[datetime.now(VIENNA).strftime('%Y-%m')])[0]
                self.send_html(layout('Zeiten',records_page(db,user,csrf,month),user,csrf));return
            if path=='/team' and user['role']!='employee':
                self.send_html(layout('Teamstatus',team_status_page(db,user,params.get('status',['all'])[0]),user,csrf));return
            if path=='/admin' and user['role']!='employee':
                self.send_html(layout('Verwaltung',admin_page(db,user,csrf),user,csrf));return
            if path=='/access' and user['role']=='superadmin':
                self.send_html(layout('Zugriffsfreigaben',access_page(db,user,csrf),user,csrf));return
            if path=='/audit' and user['role']!='employee':
                self.send_html(layout('Protokoll',audit_page(db),user,csrf));return
            if path=='/edit' and user['role']!='employee':
                try: shid=int(params.get('id',[0])[0])
                except ValueError: shid=0
                sh=db.execute('SELECT * FROM shifts WHERE id=?',(shid,)).fetchone()
                if not sh:
                    self.send_html(layout('Fehler','Eintrag nicht gefunden.',user,csrf),404);return
                owner=db.execute('SELECT role FROM users WHERE id=?',(sh['user_id'],)).fetchone()
                if owner and owner['role']=='superadmin' and user['role']!='superadmin':
                    self.send_html(layout('Zugriff verweigert','Keine Berechtigung für diese Korrektur.',user,csrf),403);return
                self.send_html(layout('Korrektur',edit_page(db,user,csrf,sh),user,csrf));return
            if path=='/password':
                msg='<p class="warn">Bitte zuerst dein vorläufiges Passwort ändern.</p>' if user['must_change'] else ''
                content=f'''<h2>Eigenes Passwort ändern</h2><section class="card" style="max-width:500px">{msg}<form method="POST" action="/password">{csrf_input(csrf)}<label>Aktuelles Passwort</label><input type="password" name="old" required><label>Neues Passwort (mindestens 12 Zeichen)</label><input type="password" name="new" minlength="12" required><label>Neues Passwort wiederholen</label><input type="password" name="confirm" minlength="12" required><p><button>Passwort ändern</button></p></form></section>'''
                self.send_html(layout('Passwort',content,user,csrf));return
            if path=='/export':
                month=params.get('month',[datetime.now(VIENNA).strftime('%Y-%m')])[0]
                if not re.fullmatch(r'\d{4}-(0[1-9]|1[012])', month):
                    self.send_html(layout('Fehler','Ungültiger Monat',user,csrf),400);return
                rows=[r for r in allowed_records(db,user) if parse_dt(r['started_at']).astimezone(VIENNA).strftime('%Y-%m')==month]
                out=io.StringIO();w=csv.writer(out,delimiter=';');w.writerow(['Name','Beginn (Wien)','Ende (Wien)','Pause Minuten','Netto Minuten','Netto Stunden'])
                for r in rows:
                    net,pause=shift_minutes(db,r)
                    w.writerow([csv_safe_cell(r['name']),local(r['started_at']),local(r['ended_at']),pause,net,f'{net/60:.2f}'.replace('.',',')])
                data= ('\ufeff'+out.getvalue()).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type','text/csv; charset=utf-8')
                self.send_header('Content-Disposition',f'attachment; filename="arbeitszeit-{month}.csv"')
                self.send_header('Content-Length',str(len(data)))
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                self.end_headers();self.wfile.write(data);return
            self.send_html(layout('Nicht gefunden','Seite nicht gefunden.',user,csrf),404)

    def do_POST(self):
        path=urllib.parse.urlsplit(self.path).path
        if not self.same_origin():
            self.send_html(layout('Fehler','Anfrage nicht zulässig.'),403);return
        try:
            data=self.get_form()
        except (ValueError, UnicodeError):
            self.send_html(layout('Fehler','Ungültige Eingabe.'),400);return
        with conn() as db:
            user,token_hash=self.context(db)
            if path=='/login':
                identity=data.get('email','').strip().lower()[:254]
                ip=self.request_client_ip() or 'unknown'
                # Gemeinsames Kontingent pro E-Mail und IP (simple lokale Sperre).
                cutoff=int(time.time())-900
                db.execute('DELETE FROM login_attempts WHERE attempted_at<?',(cutoff,))
                db.execute('DELETE FROM sessions WHERE expires_at<?',(int(time.time()),))
                idkey='mail:'+identity; ipkey='ip:'+ip
                blocked=(db.execute('SELECT count(*) FROM login_attempts WHERE identity=?',(idkey,)).fetchone()[0]>=10
                         or db.execute('SELECT count(*) FROM login_attempts WHERE identity=?',(ipkey,)).fetchone()[0]>=100)
                r=db.execute('SELECT * FROM users WHERE email=? AND active=1',(identity,)).fetchone()
                if (blocked or not r or not verify_password(data.get('password',''),r['password_hash'])
                        or (r['mfa_secret'] and not verify_totp(r['mfa_secret'],data.get('code','')))):
                    db.execute('INSERT INTO login_attempts(identity,attempted_at) VALUES(?,?)',(idkey,int(time.time())))
                    db.execute('INSERT INTO login_attempts(identity,attempted_at) VALUES(?,?)',(ipkey,int(time.time())))
                    db.commit()
                    self.send_html(layout('Anmeldung', '<section class="card" style="max-width:430px;margin:32px auto"><p class="flash err">Anmeldung fehlgeschlagen oder vorübergehend gesperrt.</p><a href="/login">Zurück zur Anmeldung</a></section>'),401);return
                if not self.network_allowed(r):
                    audit(db,r['id'],'remote_login_denied',f'user:{r["id"]}', 'Nicht freigegebenes Netzwerk')
                    db.commit()
                    self.send_html(layout('Zugriff verweigert', '<section class="card">Anmeldung aus diesem Netzwerk nicht freigegeben.</section>'), 403);return
                db.execute('DELETE FROM login_attempts WHERE identity IN (?,?)',(idkey,ipkey))
                token=secrets.token_urlsafe(32)
                db.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)',
                           (hashlib.sha256(token.encode()).hexdigest(),r['id'],secrets.token_urlsafe(24),int(time.time())+SESSION_SECONDS))
                audit(db,r['id'],'login',f'user:{r["id"]}')
                cookie=f'az_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECONDS}'+('; Secure' if SECURE_COOKIES else '')
                db.commit()
                self.redirect('/password' if r['must_change'] else '/',cookie);return
            if not user:
                self.redirect('/login');return
            if not self.network_allowed(user):
                self.send_html(layout('Zugriff verweigert','Zugriff aus diesem Netz für dieses Konto nicht freigegeben.'),403);return
            if not hmac.compare_digest(str(data.get('csrf','')),user['csrf']):
                self.send_html(layout('Fehler','Sitzungsprüfung fehlgeschlagen.',user,user['csrf']),403);return
            if user['must_change'] and path not in ('/password','/logout'):
                self.redirect('/password');return
            if REQUIRE_ADMIN_MFA and user['role']!='employee' and not user['mfa_secret'] and path not in ('/mfa-start','/mfa-confirm','/logout','/password'):
                self.redirect('/security');return
            if path=='/logout':
                db.execute('DELETE FROM sessions WHERE token_hash=?',(token_hash,))
                cookie='az_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'+('; Secure' if SECURE_COOKIES else '')
                db.commit()
                self.redirect('/login',cookie);return
            try:
                if path=='/mfa-start':
                    if user['mfa_secret']:
                        raise ValueError('Zwei-Faktor-Anmeldung ist bereits aktiviert.')
                    new_secret = new_totp_secret()
                    db.execute('UPDATE users SET mfa_pending_secret=? WHERE id=?', (new_secret,user['id']))
                    audit(db,user['id'],'mfa_enrollment_started',f'user:{user["id"]}')
                    db.commit()
                    self.redirect('/security');return
                if path=='/mfa-confirm':
                    secret=user['mfa_pending_secret']
                    if not secret or not verify_totp(secret,data.get('code','')):
                        raise ValueError('Authenticator-Code stimmt nicht überein.')
                    db.execute('UPDATE users SET mfa_secret=?,mfa_pending_secret=NULL WHERE id=?',
                               (secret,user['id']))
                    db.execute('DELETE FROM sessions WHERE user_id=? AND token_hash<>?',
                               (user['id'],token_hash))
                    audit(db,user['id'],'mfa_enabled',f'user:{user["id"]}')
                    db.commit()
                    self.redirect('/security');return
                if path=='/mfa-disable':
                    if REQUIRE_ADMIN_MFA and user['role']!='employee':
                        raise ValueError('Für Administrationskonten ist MFA vorgeschrieben.')
                    if not user['mfa_secret'] or not verify_password(data.get('password',''),user['password_hash']) or not verify_totp(user['mfa_secret'],data.get('code','')):
                        raise ValueError('Passwort oder Authenticator-Code ungültig.')
                    db.execute('UPDATE users SET mfa_secret=NULL,mfa_pending_secret=NULL WHERE id=?', (user['id'],))
                    db.execute('DELETE FROM sessions WHERE user_id=? AND token_hash<>?',
                               (user['id'],token_hash))
                    audit(db,user['id'],'mfa_disabled',f'user:{user["id"]}')
                    db.commit()
                    self.redirect('/security');return
                if path=='/access' and user['role']=='superadmin':
                    grant_remote(db,user,int(data.get('user_id','0')),int(data.get('days','0')),data.get('reason',''))
                    db.commit()
                    self.redirect('/access');return
                if path=='/password':
                    old=data.get('old','');new=data.get('new','')
                    if not verify_password(old,user['password_hash']): raise ValueError('Bisheriges Passwort ist falsch.')
                    if len(new)<12 or len(new)>128 or new!=data.get('confirm'):
                        raise ValueError('Das neue Passwort muss 12–128 Zeichen haben und übereinstimmen.')
                    if new==old: raise ValueError('Bitte ein anderes Passwort verwenden.')
                    db.execute('UPDATE users SET password_hash=?,must_change=0 WHERE id=?',(hash_password(new),user['id']))
                    # Alle fremden Sitzungen beenden.
                    db.execute('DELETE FROM sessions WHERE user_id=? AND token_hash<>?', (user['id'],token_hash))
                    audit(db,user['id'],'password_changed',f'user:{user["id"]}')
                    db.commit()
                    self.redirect('/');return
                if path=='/request-correction':
                    submit_correction(db,user,int(data.get('shift_id') or 0),
                                      data.get('start',''),data.get('end',''),data.get('reason',''))
                    db.commit()
                    self.redirect('/corrections');return
                if path=='/review-correction' and user['role']!='employee':
                    review_correction(db,user,int(data.get('request_id') or 0),
                                      data.get('decision',''),data.get('note',''))
                    db.commit()
                    self.redirect('/corrections');return
                if path=='/set-target' and user['role']!='employee':
                    target=db.execute('SELECT id,role FROM users WHERE id=?',
                                      (int(data.get('user_id') or 0),)).fetchone()
                    if not target or (target['role']=='superadmin' and user['role']!='superadmin'):
                        raise ValueError('Konto nicht gefunden oder keine Berechtigung.')
                    raw=data.get('weekly_hours','')
                    from decimal import Decimal, InvalidOperation
                    try:
                        number=Decimal(raw)
                    except InvalidOperation:
                        raise ValueError('Ungültige Sollzeit.')
                    if not number.is_finite() or number < 0 or number > 60 or number * 4 != (number * 4).to_integral_value():
                        raise ValueError('Sollzeit zwischen 0 und 60 Stunden in Viertelstundenschritten eingeben.')
                    minutes=int(number*60)
                    db.execute('UPDATE users SET weekly_target_minutes=? WHERE id=?',
                               (minutes,target['id']))
                    audit(db,user['id'],'weekly_target_changed',f'user:{target["id"]}',
                          f'{minutes} Minuten pro Woche')
                    db.commit()
                    self.redirect('/admin');return
                if path=='/punch':
                    punch_once(db,user['id'],data.get('action',''),data.get('request_id',''))
                    db.commit()
                    self.redirect('/');return
                if path=='/create-user' and user['role']!='employee':
                    role=data.get('role','employee')
                    if role=='superadmin' or (role=='admin' and user['role']!='superadmin'):
                        raise ValueError('Für diese Rolle fehlen Berechtigungen.')
                    pw=create_user(db,user['id'],data.get('name',''),data.get('email',''),role)
                    content=f'''<h2>Neues Konto angelegt</h2><section class="card" style="max-width:640px"><p>Das Startpasswort wird nur hier einmal angezeigt. Es muss beim ersten Login geändert werden.</p><p class="quiet"><code style="font-size:20px;overflow-wrap:anywhere">{esc(pw)}</code></p><p>Bitte sicher und persönlich übermitteln, nicht als unverschlüsselte Sammel-E-Mail.</p><a href="/admin" class="btn">Zur Verwaltung</a></section>'''
                    db.commit()
                    self.send_html(layout('Zugang erstellt',content,user,user['csrf']));return
                if path=='/toggle-user' and user['role']!='employee':
                    target=db.execute('SELECT * FROM users WHERE id=?',(int(data.get('user_id','0')),)).fetchone()
                    if not target: raise ValueError('Konto nicht gefunden.')
                    if target['role']=='superadmin' or (target['role']=='admin' and user['role']!='superadmin') or target['id']==user['id']:
                        raise ValueError('Dieses Konto darf nicht geändert werden.')
                    if not target['active'] and db.execute('SELECT count(*) FROM users WHERE active=1').fetchone()[0]>=CAPACITY:
                        raise ValueError(f'Es sind bereits {CAPACITY} Konten aktiv.')
                    new=1-target['active']
                    db.execute('UPDATE users SET active=? WHERE id=?',(new,target['id']))
                    if not new: db.execute('DELETE FROM sessions WHERE user_id=?',(target['id'],))
                    audit(db,user['id'],'user_activated' if new else 'user_deactivated', f'user:{target["id"]}')
                    db.commit()
                    self.redirect('/admin');return
                if path=='/edit' and user['role']!='employee':
                    sh=db.execute('SELECT * FROM shifts WHERE id=?',(int(data.get('shift_id','0')),)).fetchone()
                    if not sh: raise ValueError('Schicht nicht gefunden.')
                    owner=db.execute('SELECT role FROM users WHERE id=?',(sh['user_id'],)).fetchone()
                    if owner and owner['role']=='superadmin' and user['role']!='superadmin':
                        raise ValueError('Superadministrator-Zeiten können nur von der Superadministration korrigiert werden.')
                    reason=data.get('reason','').strip()
                    if len(reason)<5: raise ValueError('Bitte eine aussagekräftige Begründung eintragen.')
                    start=from_local_input(data.get('start',''))
                    end=from_local_input(data.get('end',''))
                    if parse_dt(end)<=parse_dt(start): raise ValueError('Ende muss nach dem Beginn liegen.')
                    if (parse_dt(end)-parse_dt(start)).total_seconds()>48*3600: raise ValueError('Schicht ist länger als 48 Stunden.')
                    # Keine Pause darf nach den neuen Schichtgrenzen liegen.
                    for b in db.execute('SELECT * FROM breaks WHERE shift_id=?',(sh['id'],)):
                        if not b['ended_at']: raise ValueError('Offene Pause zuerst regulär beenden.')
                        if parse_dt(b['started_at'])<parse_dt(start) or parse_dt(b['ended_at'])>parse_dt(end):
                            raise ValueError('Vorhandene Pause liegt außerhalb der korrigierten Schicht.')
                    # Pro Person dürfen Schichten sich nicht überschneiden.
                    overlaps=db.execute('SELECT * FROM shifts WHERE user_id=? AND id<>?',(sh['user_id'],sh['id'])).fetchall()
                    for other in overlaps:
                        if parse_dt(start)<parse_dt(other['ended_at'] or utc_now()) and parse_dt(end)>parse_dt(other['started_at']):
                            raise ValueError('Die korrigierte Zeit überschneidet sich mit einer anderen Schicht.')
                    db.execute('UPDATE shifts SET started_at=?,ended_at=?,edited_at=?,edited_by=? WHERE id=?',
                               (start,end,utc_now(),user['id'],sh['id']))
                    audit(db,user['id'],'shift_corrected',f'shift:{sh["id"]}',f'{reason[:300]} | Alt: {sh["started_at"]} bis {sh["ended_at"]} | Neu: {start} bis {end}')
                    db.commit()
                    self.redirect('/records');return
                self.send_html(layout('Nicht gefunden','Aktion nicht gefunden.',user,user['csrf']),404);return
            except (ValueError,PermissionError,sqlite3.IntegrityError) as exc:
                db.rollback()
                msg='Dieses Benutzerkonto existiert möglicherweise bereits.' if isinstance(exc,sqlite3.IntegrityError) else str(exc)
                self.send_html(layout('Eingabe prüfen',f'<section class="card"><h2>Aktion nicht möglich</h2><p class="flash err">{esc(msg)}</p><p><a href="/">Zur Stempeluhr</a> · <a href="/admin">Zur Verwaltung</a></p></section>',user,user['csrf']),400)


def bootstrap():
    init_db()
    with conn() as db:
        if db.execute('SELECT count(*) FROM users').fetchone()[0]:
            print('Es existieren bereits Benutzer. Initialisierung wurde nicht wiederholt.')
            return
        if not SUPER_EMAIL or not ADMIN_EMAIL or SUPER_EMAIL.lower()==ADMIN_EMAIL.lower():
            print('Bitte APP_SUPER_EMAIL und APP_ADMIN_EMAIL mit verschiedenen Adressen setzen.', file=sys.stderr)
            sys.exit(2)
        print('Initialisiere Arbeitszeit 30. Die Startpasswörter werden nur einmal ausgegeben.\n')
        sup = create_user(db,None,'Superadministrator',SUPER_EMAIL,'superadmin')
        adm = create_user(db,None,ADMIN_NAME,ADMIN_EMAIL,'admin')
        print(f'SUPERADMIN: {SUPER_EMAIL}\nStartpasswort: {sup}\n')
        print(f'ADMIN: {ADMIN_EMAIL}\nStartpasswort: {adm}\n')
        print('WICHTIG: Passwörter privat sichern, beim ersten Login ändern; nicht im Quellcode speichern.')


def main():
    parser=argparse.ArgumentParser(description='Arbeitszeit 30')
    parser.add_argument('command',choices=['init','serve'])
    parser.add_argument('--host',default='127.0.0.1',help='Standard: 127.0.0.1')
    parser.add_argument('--port',type=int,default=8000)
    args=parser.parse_args()
    if args.command=='init':
        bootstrap();return
    if not DB_PATH.exists():
        print('Bitte zuerst python server.py init ausführen.');sys.exit(1)
    if args.host not in ('127.0.0.1','localhost','::1') and not SECURE_COOKIES:
        print('WARNUNG: Externer Betrieb ohne HTTPS/Secure-Cookies ist unsicher. APP_SECURE_COOKIES=1 und HTTPS-Proxy erforderlich.',file=sys.stderr)
    with ThreadingHTTPServer((args.host,args.port),Handler) as web:
        print(f'Arbeitszeit 30 läuft auf http://{args.host}:{args.port}')
        web.serve_forever()


if __name__=='__main__':
    main()
