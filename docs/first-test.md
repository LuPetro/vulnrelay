# Erster Abnahmetest

Dieser Ablauf prüft die Alpha vor weiteren Funktionen. Die automatisierten Tests verwenden simulierte Quellen und Telegram-Antworten. Sie beweisen weder die Berechtigung deines echten Bots noch die Erreichbarkeit von Telegram auf deinem Rechner.

## Start und Vorbereitung

Verwende den aktuellen Stand von `development`. Folge der Docker-Installation in der [README](../README.md) und der [Telegram-Anleitung](telegram.md). Trage den Bot-Token ausschließlich lokal in `.env` ein, niemals in Issues oder Chat-Nachrichten. Nach Änderungen an `.env` die Container mit `docker compose up -d --force-recreate` neu erstellen; ein bloßer Container-Neustart übernimmt geänderte Umgebungsvariablen nicht.

Öffne `http://localhost:8080` auf dem Rechner, auf dem VulnRelay läuft. Bei einer Installation auf deinem Server nutze einen SSH-Tunnel, beispielsweise `ssh -L 8080:127.0.0.1:8080 BENUTZER@SERVER`, und öffne die lokale Adresse. Die Alpha bleibt an localhost gebunden.

```sh
docker compose ps
docker compose exec vulnrelay vulnrelay doctor
docker compose exec monitor vulnrelay engine-health
```

Erwartung: API und Monitor sind gesund. Prüfe in der Oberfläche den Worker-Heartbeat sowie Status und Zeitpunkt der letzten erfolgreichen Synchronisationen für NVD, CISA und EPSS. Der erste Quellenlauf kann mehrere Minuten dauern; Quellen können vorübergehend nicht verfügbar sein und EPSS muss nicht für jeden CVE vorliegen. Bei Fehlern den Abnahmeschritt offen lassen und den Fehler aus Overview notieren.

## 1. Echten Telegram-Kanal prüfen

Lege unter **Connectors** dein Ziel an und klicke **Test**. Die Testnachricht muss tatsächlich im richtigen privaten Testchat oder Testkanal ankommen. Im Verlauf muss dieselbe Zustellung `sent` zeigen. Nur ein erfolgreicher Klick oder ein Eintrag `pending` reicht nicht. Damit sind Zugangsdaten und Versand geprüft; Asset-Matching und Regeln noch nicht.

## 2. Asset und Regel ohne Versand prüfen

Lege zunächst ein Asset und eine Regel für dieses Asset und dein Testziel an. Neue Regeln sind standardmäßig aktiv: Entferne daher **Rule enabled**, bevor du die Testregel speicherst. Verwende **Test rule**: Das funktioniert auch bei deaktivierter Regel und sendet nichts. Prüfe CVE, Produkt, Regelbegründung und Trefferqualität. Ein Produkt- oder Schlüsselworttreffer ist keine Bestätigung, dass eine installierte Version betroffen ist. Allgemeine Versionsbereiche werden noch nicht ausgewertet.

Zusätzlicher Fehlertest: Ein CPE-Asset mit `cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*` und installiertem Versionsfeld `2.0` darf sich nicht speichern lassen. Die Oberfläche muss den Versionskonflikt erklären. Dieses Beispiel ist synthetisch und soll kein echtes Asset darstellen.

## 3. Einen echten CVE kontrolliert zustellen

Wähle aus dem Regeltest einen gespeicherten CVE mit `matched: true`. Falls kein passender Datensatz vorhanden ist, ist dieser Schritt noch nicht bestanden. Für einen gezielten Funktionstest kannst du alternativ ein ausdrücklich als Test gekennzeichnetes Asset zu einem vorhandenen CVE in einer separaten Testgruppe anlegen. Das bestätigt keine Betroffenheit deiner eigenen Systeme.

Stoppe den Monitor, bevor du die Testregel aktivierst. Damit wertet er während dieses Schritts nicht den gesamten Bestand aus:

```sh
docker compose stop monitor
docker compose exec vulnrelay vulnrelay rules list
```

Aktiviere die Testregel in der Oberfläche. Verwende für diesen Schritt genau ein ausgewähltes Asset und ein Ziel. Ersetze `RULE_ID` und `CVE_ID` durch die tatsächlichen Werte:

```sh
docker compose exec vulnrelay vulnrelay evaluate --rule-id RULE_ID --cve-id CVE_ID --enqueue
docker compose exec vulnrelay vulnrelay deliver
```

Erwartung bei leerer Warteschlange: eine neu eingeplante Meldung und anschließend `sent`. Im Telegram-Chat müssen CVE, Asset, Regelbegründung und Quellenlink stimmen. `deliver` verarbeitet die nächste fällige Meldung; bei bereits vorhandener Warteschlange zuerst den Verlauf prüfen, statt von einer leeren Warteschlange auszugehen.

## 4. Duplikatschutz und Neustart prüfen

Führe denselben `evaluate`-Befehl erneut aus. Ohne relevante Datenänderung muss `queued` jetzt `0` sein. Starte die API neu, prüfe den erhaltenen Bestand und wiederhole die Auswertung:

```sh
docker compose restart vulnrelay
docker compose up -d --wait vulnrelay
docker compose exec vulnrelay vulnrelay history
docker compose exec vulnrelay vulnrelay evaluate --rule-id RULE_ID --cve-id CVE_ID --enqueue
```

Erwartung: Asset, Regel und Versandhistorie bleiben erhalten; die unveränderte Meldung wird nicht erneut eingeplant. Kein `down -v` verwenden: Das würde das Datenvolume löschen. Eine Wiederholung nach einem Absturz genau zwischen Telegram-Annahme und lokaler Bestätigung bleibt bei At-least-once-Zustellung möglich.

## 5. Deaktivierte Regel stoppt eine wartende Meldung

Lege mit weiterhin gestopptem Monitor eine zweite, zunächst deaktivierte Testregel mit neuem Namen und eigenständiger ID an. Nach dem Regeltest aktivieren und mit deren ID gezielt denselben CVE einplanen. **Noch nicht `deliver` ausführen.** Deaktiviere diese zweite Regel wieder und führe anschließend `deliver` aus. Die Testwarteschlange sollte keine anderen fälligen Einträge enthalten: `deliver` bearbeitet den nächsten fälligen Eintrag über alle Regeln und Ziele hinweg.

Erwartung: `cancelled` mit dem Grund `Rule disabled or removed`, keine neue Telegram-Nachricht. Der Verlauf bleibt sichtbar. Das gilt auch für zwischenzeitlich entfernte Assets, geänderte Auswahl/Filter und inzwischen abgelehnte CVEs. Eine bereits laufende HTTP-Anfrage kann durch nachträgliches Deaktivieren nicht zurückgerufen werden.

Deaktiviere beide Testregeln vor dem erneuten Start des Monitors:

```sh
docker compose up -d --wait monitor
docker compose exec monitor vulnrelay engine-health
```

Erwartung: Der Monitor wird wieder gesund und die gespeicherte Konfiguration bleibt erhalten. Prüfe anschließend deine echten Regeln, bevor du sie aktivierst: Die erste Auswertung kann auch bereits vorhandene relevante CVEs melden, nicht nur zukünftig veröffentlichte.

## Ergebnis festhalten

Optionaler OpenCVE-Test: Öffne einen gespeicherten CVE unter **Vulnerabilities**, klicke **Load OpenCVE details** und prüfe **Separate OpenCVE assessment**. Bei vorhandener NVD-Bewertung bleibt sie die primäre Bewertung. Eine Fehlermeldung oder ein fehlender OpenCVE-Datensatz muss sichtbar werden, ohne gespeicherte Daten zu löschen. Die [OpenCVE-Anleitung](opencve.md) beschreibt Hintergrundaktualisierung und Grenzen. Prüfe diese Erweiterung zunächst mit deaktivierten Regeln, bevor du angereicherte Daten automatisch auswerten lässt.

Notiere den getesteten Commit, Betriebssystem/Docker-Version und für die fünf Schritte jeweils bestanden oder den konkreten Fehler. Für den späteren Dauerbetrieb zusätzlich [Backup und Wiederherstellung](backup-and-upgrade.md) auf einer separaten Installation üben. Token und private Inventardaten gehören nicht in einen Fehlerbericht. Erst ein tatsächlich empfangener CVE-Alert schließt den bisher offenen Telegram-End-to-End-Nachweis ab.
