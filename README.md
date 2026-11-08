# Arbeitszeit 30

[![APK & Tests](https://github.com/dmpcwien/Arbeitszeit-30/actions/workflows/build-apk.yml/badge.svg?branch=main)](https://github.com/dmpcwien/Arbeitszeit-30/actions/workflows/build-apk.yml)

Interne Zeiterfassung als Übergangslösung für bis zu 30 aktive Konten in VZA7.
Die App erfasst **gebuchte** Arbeitszeiten, Pausen und Korrekturen. Sie ist
**kein** automatischer Anwesenheitsnachweis und keine fertige Lohnabrechnung.

## Funktionen (v1.10 – schrittweiser Ausbau)

- Stempelaktionen: Arbeitsbeginn, Pause starten/beenden, Feierabend
- Serverseitig idempotente Stempelvorgänge bei erneut gesendeten Formularen
- Eigenes Wochen-Soll-/Ist-Stundenkonto (durch Administrator konfigurierbar)
- Tages-, Wochen- und Monatsübersicht sowie persönlicher Monatskalender
- Sekündlich aktualisierte Anzeige der laufenden Nettozeit im sichtbaren Dashboard,
  ohne regelmäßige Netzwerk-Abfragen und ohne Hintergrundaktivität
- Monatsbericht als CSV, PDF oder Excel (.xlsx); keine dauerhafte Dateiablage am Server
- Im Android-Client: genehmigte Berichtdownloads, Netzwerkfehler-Anzeige und
  Schaltfläche zum erneuten Laden
- Korrekturanträge durch Mitarbeiter mit separater Admin-Freigabe und Auditspur
- Pausenhinweise und sichtbarer Status offener Korrekturanträge
- Automatischer Hell-/Dunkelmodus anhand des Geräts
- Optionales TOTP-MFA; in der internen Docker-Vorlage für Administratoren verpflichtend
- Eigene Stundenübersicht und monatlicher CSV-Export
- Teamstatus für Administratoren mit Statusfilter (Dienst/Pause/Nicht eingestempelt)
- Korrekturen durch Berechtigte mit Pflichtbegründung und Audit-Protokoll
- Benutzerverwaltung für maximal 30 aktive Konten einschließlich Administratoren
- Rollen: Mitarbeiter, Administrator, Superadministrator
- Netzwerkbeschränkung mit zeitlich begrenzten externen Ausnahmen (1/7/30 Tage)
- Android-App als HTTPS-WebView für den zentralen Server

## Rollen

Der Superadministrator ist mit dem im Python-Code konfigurierten Superadmin-Konto
vorgesehen; Konrad Hillbrand ist als Administrator angelegt. Beide erhalten bei
der einmaligen Initialisierung zufällig erzeugte Startpasswörter, die nicht ins
Repository gehören. Die tatsächlichen Rechte werden serverseitig geprüft.

## Lokaler Test (Python 3.10+)

Die Web-/Backend-Anwendung benötigt Python 3.12 sowie die PDF-Bibliothek
aus requirements.txt. Die Excel-Ausgabe verwendet ausschließlich
Python-Standardbibliotheken.

    python -m pip install -r requirements.txt

    python -m unittest discover -s tests -v

Für die Erstinitialisierung eines **neuen** lokalen Servers müssen
`APP_SUPER_EMAIL` und `APP_ADMIN_EMAIL` als zwei unterschiedliche
E-Mail-Adressen in der Umgebung gesetzt werden. Optional lässt sich
`APP_ADMIN_NAME` setzen. Diese Angaben gehören nicht in den öffentlichen
Quellcode. Die bestehenden Konten in einer bereits vorhandenen Datenbank
bleiben davon unberührt.

    python server.py init
    python server.py serve --host 127.0.0.1 --port 8000

Lokal unter http://127.0.0.1:8000 testen. Bestehende Daten niemals löschen
oder erneut initialisieren. Die Datenbank liegt standardmäßig unter
`data/arbeitszeit.sqlite3`. Produktive Datensicherung muss durch die IT
abgenommen werden.

**Interner Docker-Server:** Die vorbereitete, aber noch nicht ausgerollte
Konfiguration und Checkliste stehen unter [deploy/README.md](deploy/README.md).
Öffentliches Hosting oder eine Render-Instanz wurden nicht eingerichtet.

## Voraussetzung für den Einsatz

**Noch nicht produktiv bereitgestellt:** Die APK allein speichert keine
gemeinsamen Arbeitszeiten. Die Universität muss den zentralen Server,
den HTTPS-Reverse-Proxy, die freigegebenen IP-Netze, das Berechtigungs- und
Datenschutzkonzept sowie Backups und Zugriffsschutz freigeben.

Erforderliche Konfiguration bei Betrieb hinter dem HTTPS-Proxy:

- APP_UNI_CIDRS: geprüfte, komma-separierte Uni-Netze; Standard erlaubt
  ausschließlich Loopback (127.0.0.1/32,::1/128).
- APP_TRUSTED_PROXY_CIDRS: ausschließlich die tatsächlichen Proxy-IP-Netze.
  Der Proxy muss X-Real-IP selbst setzen/überschreiben.
- APP_SECURE_COOKIES=1: erzwingt Secure-Cookies am Browser/HTTPS-Zugang.
- APP_DATA_DIR: geschützter dauerhafter Speicherort der SQLite-Datenbank.

Der Python-Server sollte lokal gebunden bleiben. Nicht direkt unverschlüsselt
ins Internet stellen. Externe Zugriffsfreigaben ersetzen keine IT-Freigabe,
Gerätekontrolle oder MFA. Bei verteiltem oder besonders hohem Lastbetrieb
wäre eine professionelle Server-/Datenbanklösung erforderlich.

## Mehrbenutzer-Integrationstests

Die Tests unter tests/ überprüfen auch TOTP-Anmeldung und Pflicht-MFA,
Korrekturen, Datenbankmigration, Rücksicherung eines Datenbank-Snapshots,
Monatskalender, Live-Zeitanzeige, Berichtexporte und idempotente Buchungen.

Die Testdatei tests/test_http_integration.py simuliert drei unabhängige Konten
in einem lokalen HTTP-Server mit temporärer Datenbank. Sie überprüft Login,
Arbeitsbeginn, Pause, Feierabend, eingeschränkte Mitarbeiteransichten,
Admin-Teamstatus, CSV-Export, CSRF-Schutz und das Sperren eines Kontos.
Es werden keine produktiven Benutzer oder echten Universitätsserver verwendet.

## Android-APK

Der GitHub-Actions-Workflow build-apk.yml installiert die PDF-Bibliothek,
prüft Python-Syntax und Regressionstests und baut anschließend eine
**Debug-APK** (Version 1.10.0). Das APK-Artefakt heißt
Arbeitszeit-30-APK und wird nach **einem Tag** automatisch aus Actions
entfernt. Die App verlangt beim ersten Start die HTTPS-Adresse des bereits
bereitgestellten Servers.

Die Debug-APK ist kein signiertes Release und eine Update-Installation
zwischen Builds ist nicht garantiert. Für produktiven Rollout eine stabile
Release-Signatur, kontrollierte Verteilung und Endgerätetests einrichten.

## Datenschutz und Aufbewahrung

Zeiten und Namen sind personenbezogene Beschäftigtendaten. Vor einer echten
Einführung sind insbesondere innerbetriebliche Zuständigkeit,
Betriebsrats-/Datenschutzprüfung, Protokollzugriffe, Lösch-/Aufbewahrungsfristen,
Informationspflichten und die IT-Sicherheitsabnahme zu klären.
