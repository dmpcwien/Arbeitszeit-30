# QA-Prüfplan für Arbeitszeit 30 v1.11

Diese Branch enthält nur diesen Prüfplan. Die Anwendung und alle vorhandenen
Buchungen befinden sich weiterhin unverändert auf main.

Prüfpunkte:
- Python-Tests für neue Dienstpläne und nachträgliche DB-Migration
- Zwei getrennte Mitarbeiterkonten + Admin-Testkonto
- Ein-/Ausstempeln und kein Zugriff auf fremde Zeiten
- Live-Teamstatus und Prüfhilfe (keine automatische Arbeitszeitänderung)
- Sicherer Release-Workflow: Debug-Build ohne Secrets, signierter Build nur
  mit dauerhaftem Keystore
- Kein Uni-Server und keine echten Personaldaten
