# Arbeitszeit 30

Interne Zeiterfassung als Übergangslösung für bis zu 30 aktive Konten in VZA7.
Die App erfasst **gebuchte** Arbeitszeiten, Pausen und Korrekturen. Sie ist
**kein** automatischer Anwesenheitsnachweis und keine fertige Lohnabrechnung.

## Funktionen (v1.7)

- Stempelaktionen: Arbeitsbeginn, Pause starten/beenden, Feierabend
- Eigene Stundenübersicht und monatlicher CSV-Export
- Teamstatus für Administratoren: im Dienst, in Pause, nicht eingestempelt
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

Keine externen Python-Abhängigkeiten erforderlich.

    python -m unittest discover -s tests -v
    python server.py init
    python server.py serve --host 127.0.0.1 --port 8000

Anschließend http://127.0.0.1:8000 öffnen. Das Kommando init ist nur für
eine neue Datenbank vorgesehen. **Bestehende Daten niemals für Tests löschen.**

Die Datenbank liegt unter data/arbeitszeit.sqlite3, sofern APP_DATA_DIR
nicht gesetzt ist. Sie muss serverseitig dauerhaft und geschützt gespeichert
werden. Backups müssen konsistent (SQLite-Backup oder WAL-konforme Sicherung)
erfolgen; das GitHub-Repository enthält keine Produktivdaten.

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

## Android-APK

Der GitHub-Actions-Workflow build-apk.yml führt zuerst Python-Tests aus und
baut anschließend eine **Debug-APK** (Version 1.7.0). Das APK-Artefakt heißt
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
