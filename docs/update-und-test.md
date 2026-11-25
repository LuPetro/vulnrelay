# Update und Test der neuen Funktionen

Diese Anleitung ist für die bestehende **Testinstallation** in
`~/vulnrelay-test`. Prüfe vor jedem Befehl, dass du im richtigen Benutzerkonto
und Ordner bist. Die produktive Installation und andere Projekte bleiben
unberührt. Die Datenbank wird beim Start auf die neue Version migriert; mache
deshalb zuerst eine Sicherung.

## 1. Sichern und aktualisieren

```sh
cd ~/vulnrelay-test
backup_name="vor-update-$(date -u +%Y%m%dT%H%M%SZ).db"
docker compose exec vulnrelay vulnrelay backup "/app/data/$backup_name"
docker compose cp "vulnrelay:/app/data/$backup_name" "./$backup_name"
chmod 600 "./$backup_name"
git pull --ff-only origin development
```

Wenn ein Schritt fehlschlägt, behebe den Fehler, bevor du weitermachst. Die
Sicherung enthält Inventar, Regeln und Benachrichtigungshistorie; behandle sie
vertraulich und bewahre eine weitere Kopie außerhalb des Servers auf. Deine
`.env` mit den Zugangsdaten gehört nicht zur Datenbanksicherung. **Ersetze deine
bestehende `.env` nicht durch `.env.example`.**

Danach die Testinstallation stoppen, das Image neu bauen und wieder starten:

```sh
docker compose stop
docker compose build
docker compose up -d --wait --wait-timeout 180
docker compose exec vulnrelay vulnrelay doctor
docker compose exec monitor vulnrelay engine-health
```

Öffne die bisherige Testoberfläche und lade die Seite gegebenenfalls vollständig
neu. Nutze beim Update kein `docker compose down -v`: Das würde auch das
Datenvolume löschen. Ein einfaches `git pull` allein aktualisiert das laufende
Docker-Image nicht.

## 2. Bestehende Funktionen prüfen

Prüfe, ob deine Assets, Regeln und der Telegram-Connector noch angezeigt werden.
Sende unter **Connectors** eine Testnachricht. Der Test wird wie andere
Nachrichten in die Queue gelegt und hält sich an die eingestellten Versandzeiten.
Unter **Overview** und in der Zustellhistorie siehst du Quelle, Queue und Fehler.

## 3. Paketüberwachung mit OSV testen

OSV ist zunächst ausgeschaltet. Öffne auf dem Server `nano .env` und setze die
folgende Zeile auf `true`; falls sie noch fehlt, ergänze sie:

```text
VULNRELAY_OSV_ENABLED=true
```

In Nano speicherst du mit `Strg+O`, bestätigst mit Enter und beendest mit `Strg+X`.

Übernimm die geänderte Umgebung mit `docker compose up -d --force-recreate`.
Unter **Assets → Add asset → Match by → package** kannst du beispielsweise ein
npm- oder PyPI-Paket mit einer **exakten** Version hinzufügen. OSV erhält dabei
Paketname, Ökosystem und Version; dein Assetname, deine Gruppe und deine
Zugangsdaten werden nicht gesendet. Der letzte Check oder ein Fehler wird beim
Asset angezeigt.

Alternativ kannst du bei einem Paket eine Paket-URL wie `pkg:npm/next@15.1.0`
einfügen und **Use package URL** wählen. Prüfe die ausgefüllten Felder und
speichere anschließend das Asset. Unterstützt werden Paket-URLs der sechs
OSV-Ökosysteme ohne Qualifikatoren oder Unterpfad und mit konkreter Version;
ein bloßes `latest` reicht nicht. Eine Go-Kennung muss den tatsächlichen
Modulpfad bezeichnen. Die Vorschau allein startet keine Überwachung.

Für mehrere Pakete öffnest du **Assets → Import package list** und fügst pro
Zeile eine solche Paket-URL ein. Wähle die Gruppe und nutze **Review package
list**, bevor du importierst. Bereits vorhandene und doppelte Einträge werden
angezeigt und nicht überschrieben. Neue Assets können von bestehenden Regeln
erfasst werden. Mehr dazu in der [Anleitung für Paketlisten](package-import.md).

Erstelle zum Prüfen eine passende Regel, etwa für die Testgruppe mit
`confidence equals confirmed`. Eine Regel, die zwingend CVSS ≥ 9 verlangt,
trifft einen OSV-Eintrag ohne CVSS nicht. „Confirmed“ bezieht sich auf den
OSV-Treffer für deine **angegebene** Version; VulnRelay prüft nicht selbst,
welche Version tatsächlich installiert ist. Nicht jeder OSV-Eintrag hat eine
CVE-Kennung. Details: [OSV-Anleitung](osv.md).

Nach dem Update können einzelne ältere OSV-Einträge einmal erneut gemeldet
werden, wenn ihre Änderungshistorie bisher nicht für den neuen Vergleich
gespeichert war. Reine Zeitstempeländerungen erzeugen nach der ersten
erfolgreichen Vergleichsbasis keine zusätzlichen Alerts. Unterschiedliche
Assets und Regeln sowie Zustellversuche nach einem Absturz können weiterhin
separate Nachrichten auslösen.

## 4. Wöchentlichen Bericht prüfen

Unter **Reports → Add report** wählst du **Worldwide** für zuletzt veröffentlichte
lokal gespeicherte NVD-Einträge oder **My assets** für passende aktive Regeln.
Wähle einen Connector, Zeitzone und Uhrzeit. Mit **Preview** siehst du den Inhalt
ohne Versand. Für einen praktischen Test kannst du einen täglichen Bericht für
einige Minuten später anlegen und anschließend wieder deaktivieren. Der Versand
erfolgt über die normale Queue und beachtet die Connector-Versandzeiten.

Der Bericht kann unvollständig sein, etwa wenn NVD nicht erreichbar war oder die
lokale Datenbank nicht den gesamten Zeitraum enthält. Er zeigt den letzten
erfolgreichen NVD-Sync und wie viele Kandidaten geprüft wurden. Berichte
ersetzen deine sofortigen Alerts nicht.

## 5. KI optional verbinden

Unter **AI** wählst du OpenAI, Anthropic oder ein kompatibles API-Protokoll und
trägst die genaue Modell-ID ein. Der Schlüssel gehört **auf dem Server** in die
private `.env` als `VULNRELAY_AI_KEY`; gib ihn nicht im Chat und nicht in der
Weboberfläche ein. Für kompatible Anbieter wird zusätzlich
`VULNRELAY_AI_BASE_URL` benötigt. Nach dem Bearbeiten der `.env` beide Container
mit `docker compose up -d --force-recreate` neu erstellen.

Speichere deine Einstellungen und nutze **Test connection**. Dieser echte
Testaufruf kann Kosten bei deinem Anbieter verursachen. Erst wenn du die
Zusammenfassungen ausdrücklich aktivierst, werden für passende Alerts die
öffentliche CVE-Kennung und Beschreibung an den Anbieter gesendet. KI-Ausgaben
sind als unbestätigt gekennzeichnet; bei Fehlern wird der normale Alert trotzdem
versendet. Das Tageslimit begrenzt Anfragen, nicht direkt den Geldbetrag. Weitere
Einzelheiten stehen in der [KI-Anleitung](ai.md).

## 6. Weitere Ziele

Discord und Slack verwenden Webhook-URLs in der `.env`; E-Mail verwendet einen
SMTP-Server mit STARTTLS. Für eigene Dienste gibt es einen generischen JSON-
Webhook mit optionaler Signatur. Für Push-Nachrichten am Handy gibt es auch
ntfy und Gotify. Öffentliche ntfy-Themen können von anderen mitgelesen werden;
verwende für private Meldungen einen zugriffsgeschützten Server. Richte nur die
Kanäle ein, die du nutzen möchtest. Die jeweiligen Schritte stehen in
[Discord/Slack](webhook-connectors.md), [E-Mail](email.md),
[ntfy/Gotify](push-connectors.md) und [generischer Webhook](generic-webhook.md).
