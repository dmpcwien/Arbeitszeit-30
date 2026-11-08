#!/usr/bin/env python3
"""Konsistente SQLite-Snapshots auf separates lokales Backup-Volume.

Keine Verschlüsselung durch dieses Skript: das Backup-Volume muss durch
die Infrastruktur verschlüsselt und zusätzlich extern gesichert werden.
"""
import argparse
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

SOURCE_DB = Path(os.getenv("APP_DATA_DIR", "/data")) / "arbeitszeit.sqlite3"
BACKUP_DIR = Path(os.getenv("APP_BACKUP_DIR", "/backups"))


def backup_once(source=SOURCE_DB, target_dir=BACKUP_DIR, keep=30):
    source = Path(source)
    target_dir = Path(target_dir)
    if not source.is_file():
        raise FileNotFoundError("Quelldatenbank ist nicht vorhanden: " + str(source))
    if keep < 2 or keep > 365:
        raise ValueError("Aufbewahrung muss 2 bis 365 Sicherungen betragen.")
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target_dir, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    final = target_dir / f"arbeitszeit-{stamp}-{os.getpid()}.sqlite3"
    temporary = target_dir / (final.name + ".part")
    try:
        with sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True) as original:
            with sqlite3.connect(temporary) as snapshot:
                original.backup(snapshot)
                check = snapshot.execute("PRAGMA integrity_check").fetchone()[0]
                if check != "ok":
                    raise RuntimeError("Backup-Integritätsprüfung fehlgeschlagen.")
        os.chmod(temporary, 0o600)
        os.replace(temporary, final)
        with final.open("rb") as file:
            os.fsync(file.fileno())
        for stale in sorted(target_dir.glob("arbeitszeit-*.sqlite3"), reverse=True)[keep:]:
            stale.unlink()
    finally:
        if temporary.exists():
            temporary.unlink()
    return final


def main():
    parser = argparse.ArgumentParser(description="Arbeitszeit 30 SQLite-Sicherung")
    parser.add_argument("--loop", action="store_true", help="Im Backup-Sidecar täglich sichern.")
    parser.add_argument("--keep", type=int, default=30, help="Anzahl Sicherungen (2–365)")
    args = parser.parse_args()
    while True:
        try:
            snapshot = backup_once(keep=args.keep)
            print(f"Backup geprüft: {snapshot.name}", flush=True)
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            print(f"BACKUP-FEHLER: {exc}", flush=True)
            if not args.loop:
                raise
        if not args.loop:
            return
        time.sleep(24 * 3600)


if __name__ == "__main__":
    main()
