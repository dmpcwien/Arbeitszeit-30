# Android-Release-Signierung (v1.11)

**Status: Workflow vorbereitet; ohne vier GitHub-Secrets keine signierte Release-APK.**

## Dauerhaften Keystore erzeugen

Keystore ausschließlich auf einem vertrauenswürdigen eigenen Gerät erstellen:

    keytool -genkeypair -v -keystore arbeitszeit30-release.jks -storetype PKCS12 -alias arbeitszeit30 -keyalg RSA -keysize 3072 -validity 10000

Passwörter werden interaktiv abgefragt. Keystore und Zugangsdaten getrennt und sicher sichern. Niemals ins öffentliche GitHub-Repository oder in einen Chat hochladen.

## Vier GitHub-Actions-Secrets

Unter Repository Settings → Secrets and variables → Actions:

| Secret | Wert |
|---|---|
| AZ_RELEASE_KEYSTORE_BASE64 | Base64 der gesamten Keystore-Datei |
| AZ_RELEASE_STORE_PASSWORD | Keystore-Passwort |
| AZ_RELEASE_KEY_ALIAS | Gewählter Alias (z. B. arbeitszeit30) |
| AZ_RELEASE_KEY_PASSWORD | Passwort des privaten Schlüssels |

Base64 ist nur eine Kodierung, keine Verschlüsselung. Unter Linux:

    base64 -w 0 arbeitszeit30-release.jks

Windows PowerShell:

    [Convert]::ToBase64String([IO.File]::ReadAllBytes('arbeitszeit30-release.jks'))

Keystore-Base64 ausschließlich in das GitHub Secret einfügen, nie als Code oder Issue veröffentlichen.

## Release-Build

Die Datei .github/workflows/build-apk.yml führt Tests aus und baut standardmäßig eine Debug-APK. Nur mit allen vier Secrets wird zusätzlich via assembleRelease eine stabile signierte APK erstellt.

CI prüft die Signatur mit Android apksigner verify --print-certs. Das Artefakt heißt Arbeitszeit-30-RELEASE-SIGNED und enthält die APK und einen SHA256-Hash, mit einem Tag Aufbewahrungsfrist.

Fehlen alle Secrets, wird nur die Debug-APK erzeugt. Sind Secrets nur teilweise eingerichtet, schlägt der Build fehl. Niemals automatisch neue private Release-Schlüssel bei jedem Build erzeugen.

Ein vorhandener Debug-Build ist wegen unterschiedlicher Signatur normalerweise nicht direkt mit einem Release-Build updatefähig. Zeitbuchungen verbleiben serverseitig. Ein Upgrade zwischen zwei signierten Release-Versionen zuerst auf Testgeräten prüfen.

Der Build ersetzt weder die Uni-IT- und Datenschutzfreigabe noch eine echte Serverbereitstellung.
