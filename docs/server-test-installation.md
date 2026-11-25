# Frische Testinstallation auf dem Server

Dieser Ablauf ist ein eigenständiger Installationstest: Du klonst das Repository
selbst, baust ein eigenes Image und startest eine leere Installation unter
deinem VPS-Nutzer. Der neue Ordner ist `$HOME/vulnrelay-test`. Andere Projekte
und bereits vorhandene VulnRelay-Daten werden dabei nicht verwendet.

Deine Installation kannst du nach erfolgreicher Abnahme für den Dauerbetrieb nutzen. Der Projektstatus bleibt bis zu den ausstehenden Abnahmen Alpha. Entwicklungsänderungen werden nicht automatisch in deine Installation übernommen; du entscheidest über Updates und führst sie nach einem Backup selbst aus.

Voraussetzungen sind Git, Docker mit aktuellem Compose und Docker-Zugriff ohne sudo. Das Repository ist öffentlich; für den HTTPS-Klon brauchst du keine GitHub-Zugangsdaten. Bei bereits eingerichtetem GitHub-SSH-Zugriff kannst du alternativ `git@github.com:LuPetro/vulnrelay.git` verwenden. Zugangsdaten gehören nicht in die Clone-URL oder in Chat-Nachrichten.

## 1. Selbst frisch klonen

Die folgenden Befehle führst du in deiner SSH-Sitzung auf dem Server aus:

```sh
cd "$HOME"
git clone --branch development --single-branch https://github.com/LuPetro/vulnrelay.git vulnrelay-test
cd "$HOME/vulnrelay-test"
git rev-parse --short HEAD
cp .env.example .env
chmod 600 .env
nano .env
```

Hier wird `development` gewählt, um aktuelle Entwicklungsänderungen isoliert zu testen. Dieser Branch kann Änderungen enthalten, die noch nicht auf `main` sind. Für eine normale Neuinstallation verwende die [Schnellstartanleitung](schnellstart.md). Falls der Zielordner schon existiert, halte an und prüfe ihn; lösche oder überschreibe ihn nicht blind.

## 2. Die Testinstanz getrennt konfigurieren

Ergänze die beiden Compose-Werte und ändere den bestehenden Port in deiner neuen `.env`, sodass diese Werte jeweils genau einmal aktiv gesetzt sind:

```dotenv
COMPOSE_PROJECT_NAME=vulnrelay-test
VULNRELAY_IMAGE=vulnrelay-test:local
VULNRELAY_PORT=8081
```

Andere Werte können für den ersten Start unverändert bleiben. Ein NVD-Schlüssel und KI sind nicht erforderlich. Optional kannst du jetzt `TELEGRAM_BOT_TOKEN` eintragen, oder zunächst nur Oberfläche und Quellen testen. Verwende für Benachrichtigungen einen eigenen Testchat.

Der Compose-Projektname trennt Container, Netzwerk und Volume. Der Imagename trennt Neubauten von der Entwicklung. Port 8081 bleibt ausschließlich an `127.0.0.1` gebunden. Kopiere keine Entwicklungsdatenbank und keine Entwicklungs-`.env`. In dieser SSH-Sitzung gesetzte Umgebungsvariablen können `.env` übersteuern; kontrolliere vor dem Start die aufgelöste Konfiguration:

```sh
docker compose config --format json | python3 -c 'import json,sys; c=json.load(sys.stdin); s=c["services"]; print("Projekt:",c["name"]); print("Images:",{k:v["image"] for k,v in s.items()}); print("Port:",s["vulnrelay"]["ports"]); print("Volume:",c["volumes"]["vulnrelay-data"]["name"])'
```

Erwartet: Projekt `vulnrelay-test`, beide Images `vulnrelay-test:local`, Hostport `8081` an `127.0.0.1`, Volume `vulnrelay-test_vulnrelay-data`. Der Befehl zeigt keine Zugangsdaten. Bei abweichenden Werten erst die Konfiguration korrigieren.

## 3. Bauen und starten

Im neuen Testordner:

```sh
docker compose build
docker compose up -d --wait --wait-timeout 180
docker compose ps
docker compose exec vulnrelay vulnrelay doctor
docker compose exec monitor vulnrelay engine-health
curl --fail http://127.0.0.1:8081/ready
```

Der erste Build braucht Zeit und freien Arbeitsspeicher. `up --wait` prüft die Container, nicht den Abschluss aller Quellensynchronisationen. Erwartet werden zwei gesunde Dienste und ein erfolgreicher Bereitschaftsaufruf. Bei einem Fehler nicht mit den nächsten Schritten fortfahren; sichere Fehlermeldung und Logs:

```sh
docker compose logs --tail 100 vulnrelay monitor
```

## 4. Oberfläche vom eigenen Computer öffnen

Öffne auf deinem eigenen Computer ein zusätzliches Terminal, ersetze Benutzer und Server und lasse den Tunnel offen:

```sh
ssh -N -L 8081:127.0.0.1:8081 BENUTZER@SERVER
```

Öffne dann `http://localhost:8081`. Die öffentliche Server-IP mit Port 8081 ist hierfür nicht vorgesehen. Die Oberfläche muss mit null Assets, Regeln und Connectoren starten; CVEs werden durch den Monitor nachgeladen. Die erste NVD-Synchronisation kann mehrere Minuten dauern. Prüfe danach die Quellenzustände und Zeitstempel in Overview.

## 5. Als neuer Nutzer konfigurieren

Folge jetzt [dem ersten Abnahmetest](first-test.md) ab **1. Echten Telegram-Kanal prüfen**. Führe sämtliche Compose-Befehle weiterhin aus `$HOME/vulnrelay-test` aus. Verwende den Port 8081 für den Browser, auch wenn die allgemeine Anleitung 8080 nennt.

Nach einer späteren Tokenänderung in dieser Test-`.env`:

```sh
docker compose up -d --force-recreate --wait
```

Erst eine wirklich empfangene Telegram-Testnachricht und ein gezielt zugestellter echter CVE bestätigen den Versand. Starte mit deaktivierten Regeln und aktiviere keine breite Regel unkontrolliert: Der erste Lauf kann auch vorhandene CVEs melden.

## 6. Pausieren, fortsetzen und aktualisieren

Aus dem Testordner stoppt dieser Befehl ausschließlich die Testinstanz und bewahrt ihre Daten:

```sh
docker compose stop
```

Fortsetzen:

```sh
docker compose up -d --wait
```

Vor späteren Updates die [Backup-Anleitung](backup-and-upgrade.md) befolgen; anschließend im Testordner:

```sh
git pull --ff-only origin development
docker compose build
docker compose up -d --wait
```

Verwende kein `down -v`, wenn die Testdaten erhalten bleiben sollen. Halte Commit-ID, Installationsfehler und die Ergebnisse des Abnahmetests fest. Die Installation bleibt eine Alpha, bis die offenen Abnahmen erfüllt sind.
