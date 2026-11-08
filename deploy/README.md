# Interner Server – Betriebsanleitung (Entwurf zur IT-Abnahme)

**Status: vorbereitet, NICHT von der Uni freigegeben oder installiert.**
Keine echten Mitarbeiterdaten eingeben, bevor IT, Datenschutz, Betriebsrat und
Dienstgeber die Verwendung beurteilt und genehmigt haben.

## Architektur
- Python HTTP-Anwendung mit SQLite, im Docker-Container ohne Root-Rechte
- Docker-Port nur an `127.0.0.1:8000` des Hosts gebunden
- Davor: von der IT betriebener HTTPS-Reverse-Proxy mit TLS-Zertifikat
- Dauerhafte SQLite-Daten in dem Docker-Volume `arbeitszeit_db`
- IP-Filterung serverseitig; Proxy muss `X-Real-IP` selbst ueberschreiben
- Android APK ist nur ein WebView-Client fuer die von der IT freigegebene URL

Die Konfiguration stellt weder MFA, SSO, automatische Offsite-Backups noch
eine datenschutzrechtliche oder arbeitsrechtliche Freigabe bereit.

## Einmalige Installation durch die IT

Voraussetzungen: interner Linux-Server, aktuelle Docker-Engine mit
Compose-Plug-in, interne HTTPS-Domain, dokumentierte Client- und Proxy-IP,
Berechtigung zum Betrieb. Die hier aufgefuehrten Adressen sind keine
vorgeschlagenen Uni-IP-Adressen.

1. Repository durch die IT in eine abgesicherte Serverumgebung uebernehmen.
2. Im Repository in den Ordner `deploy/` wechseln.
3. Datei `.env.example` nach `.env` kopieren und Dateirechte auf 600 setzen.
4. Gemeinsam mit der IT `APP_UNI_CIDRS`, `APP_TRUSTED_PROXY_CIDRS`,
   `APP_SUPER_EMAIL`, `APP_ADMIN_EMAIL`, `APP_ADMIN_NAME` in `.env` setzen.
   Die IP-Netze duerfen NICHT geraten werden.
5. `docker compose config` zur Pruefung der Einstellungen ausfuehren.
6. `docker compose build` zum Bauen des Containers ausfuehren.
7. `docker compose run --rm arbeitszeit python server.py init` **einmalig**
   zur Erstinitialisierung ausfuehren. Generierte Startpasswoerter vor
   unbefugtem Zugriff schuetzen. Initialisierung nie fuer eine bestehende
   Datenbank wiederholen oder deren Volume loeschen.
8. `docker compose up -d` zum Starten verwenden.
9. `docker compose ps` zur Ueberpruefung des Dienstes ausfuehren.
10. HTTPS-Reverse-Proxy intern einrichten und abnehmen; erst danach
    Endgeraete und Mitarbeiterkonten mit rein fiktiven Testdaten pruefen.

**Achtung:** `docker compose down -v` loescht das Datenvolume und darf
nicht auf Produktivdaten angewendet werden.

## Security- und Datenschutzpruefung vor dem Start

- Beauftragte Person/Abteilung, Betriebsrat, Datenschutzverantwortliche
- Zugriffskonzept nach Rollen, Genehmigung der Teamstatus-Anzeige
- Authentifizierung inklusive MFA-/SSO-Anforderung der Uni
- Mitarbeitenden-Information, Zweckbindung, Speicherdauer, Auskunft
- Freigabe des Quellcodes und der eingesetzten Python-/Docker-Basisimages
- Zertifikatsverwaltung, HTTPS, Firewall, Netzsegmentierung, Reverse-Proxy
- Keine Internetfreigabe / keine Cloud-Nutzung ohne gesonderte Genehmigung
- Gesonderte, taeglich ueberpruefte SQLite-Backups und Wiederherstellungstests
- Updates, Monitoring, Administratorvertretung, Patchprozess, Alarmierung
- Rechtskonforme Arbeitszeit- und Pausenregeln sowie bestehende Uni-Systeme

## CSV-Export und Datenumfang

Erfasst werden Name, E-Mail-Adresse, Rolle, Status des Kontos, Beginn/Ende
von Arbeitszeiten und Pausen sowie technische Korrektur- und Auditdaten.
Der Teamstatus wird ausschliesslich Administratoren angezeigt.
Der Export enthaelt personenbezogene Daten; Weitergabe und Ablage beduerfen
eines abgestimmten Berechtigungskonzepts.

## Betrieb: bewusst noch nicht produktiv

Die App bildet erfasste Zeiten ab, aber keine rechtliche Kontrolle von
Ruhezeiten, Ueberstunden, Zeitausgleich, Urlaub oder Lohnabrechnung.
Vor Uebernahme als offizielles Zeiterfassungssystem muss die fachliche
Zustaendigkeit die Eignung pruefen. Die bestehende Zeiterfassung darf nicht
ohne Genehmigung abgeloest werden.
