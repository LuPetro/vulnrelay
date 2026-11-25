# VulnRelay installieren und testen

Diese Anleitung richtet eine **neue** Alpha-Testinstallation ein. Für eine
bereits vorhandene Installation wie `~/vulnrelay-test` nutze die
[Update- und Testanleitung](update-und-test.md); deine bestehende `.env` darf
beim Update nicht überschrieben werden.

## Voraussetzungen

Du brauchst einen Linux-Rechner oder VPS mit Git, Docker und Docker Compose
ab **2.24**. Dein Benutzer muss auf Docker zugreifen können. VulnRelay braucht
ausgehende HTTPS-Verbindungen zu den Quellen und den gewählten Zielen. Der
erste Image-Build benötigt freien Speicher und kann auf kleinen Servern dauern.

Das Repository ist momentan privat. Zum Klonen brauchst du Zugriff auf das
GitHub-Konto: Bei HTTPS funktioniert ein berechtigtes Token, nicht das
GitHub-Kontopasswort; alternativ kannst du einen eingerichteten SSH-Schlüssel
nutzen. Zugangsdaten gehören nicht in die Clone-URL oder in einen Chat.

## 1. Neu klonen und starten

Wähle einen neuen Ordner und führe die Befehle auf dem Server aus:

```sh
git clone --branch development https://github.com/LuPetro/vulnrelay.git
cd vulnrelay
cp .env.example .env
chmod 600 .env
docker compose up -d --build --wait --wait-timeout 180
docker compose ps
```

`development` enthält derzeit den aktuellen Stand; `main` ist noch nicht auf
demselben Stand. Der Start legt ein eigenes Datenvolume für diese
Compose-Installation an. Für eine **zweite** Installation neben einer
bestehenden nimm die [Anleitung mit getrenntem Port und Volume](server-test-installation.md).

## 2. Oberfläche öffnen

Auf dem Rechner, auf dem VulnRelay läuft: **http://localhost:8080**. Auf einem
entfernten VPS bleibt der Port am Server auf localhost beschränkt. Starte auf
deinem eigenen Computer einen SSH-Tunnel; ersetze dabei Benutzer und Server:

```sh
ssh -N -L 8080:127.0.0.1:8080 BENUTZER@SERVER
```

Lass das Terminal offen und öffne anschließend `http://localhost:8080` auf
deinem Computer. Ein API-Token allein macht eine öffentliche Freigabe der
Oberfläche nicht sicher; direkte Internetfreigabe ist noch nicht unterstützt.

## 3. Ersten Connector und erste Regel testen

1. Wähle unter **Catalog** oder **Assets** eine Technologie, die dich
   interessiert. Ein Produkt-Treffer allein bestätigt keine betroffene Version.
2. Für Telegram: Erstelle einen Bot und folge der [Telegram-Anleitung](telegram.md).
   Der Bot-Token gehört auf dem Server in die private `.env`; in das Formular
   kommt der **Name** der Umgebungsvariable, normalerweise `TELEGRAM_BOT_TOKEN`.
3. Nach jeder Änderung der `.env` beide Container neu erstellen:

   ```sh
   docker compose up -d --force-recreate --wait --wait-timeout 180
   ```

4. Unter **Connectors** eine Testnachricht auslösen und prüfen, ob sie wirklich
   im gewählten Chat ankommt. Versandzeiten und Queue gelten auch für Tests.
5. Unter **Notification rules** eine kleine Testregel mit passendem Asset und
   Ziel erstellen. Regeln sind standardmäßig aktiv: Entferne vor dem Speichern
   **Rule enabled**. Teste die Regel gegen gespeicherte CVEs, bevor du sie
   aktivierst. Bereits vorhandene CVEs können beim ersten Lauf gemeldet werden.

Ein erfolgreicher Connector-Test bestätigt noch keinen CVE-Alert. Für den
vollständigen Test mit Duplikatschutz und Neustart nutze den
[ersten Abnahmetest](first-test.md). Unter **Overview** siehst du Quellenstatus,
letzten erfolgreichen Abgleich, Queue und Fehler.

## 4. Prüfen, pausieren und aktualisieren

```sh
docker compose ps
docker compose exec vulnrelay vulnrelay doctor
docker compose exec monitor vulnrelay engine-health
docker compose exec monitor vulnrelay check-nvd
```

Ein erfolgreicher `check-nvd` prüft eine Verbindung, nicht den vollständigen
Abgleich. Bei NVD-Fehlern beachte den letzten erfolgreichen Sync und den
nächsten Versuch; siehe [Fehlerbehebung](troubleshooting.md). `docker compose stop`
pausiert diese Installation, `docker compose up -d --wait` startet sie
wieder. `down -v` löscht das zugehörige Datenvolume.

Vor Updates eine [Sicherung](backup-and-upgrade.md) erstellen und die
[Update-Anleitung](update-und-test.md) befolgen. KI und OSV sind standardmäßig
ausgeschaltet; ihre Einrichtung steht in [KI](ai.md) und [OSV](osv.md).
KI-Testaufrufe können Kosten beim Anbieter verursachen.
