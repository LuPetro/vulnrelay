# GitHub für die Veröffentlichung einrichten

Diese Schritte sind für die Eigentümerin oder den Eigentümer des Repositories.
Eine GitHub-App mit Zugriff auf Code kann diese administrativen Einstellungen
nicht automatisch setzen. Auf dem Smartphone kann es helfen, die
Desktop-Ansicht des Browsers zu aktivieren. Je nach GitHub-Ansicht können
Menübezeichnungen leicht abweichen.

## 1. Historie und Pull Request prüfen

1. Öffne [VulnRelay auf GitHub](https://github.com/LuPetro/vulnrelay) und
   melde dich als Eigentümer an. Das Repository ist derzeit privat.
2. Prüfe den [Entwurfs-Pull-Request](https://github.com/LuPetro/vulnrelay/pull/1)
   von `development` nach `main` und die grünen CI- und Security-Checks.
3. Entscheide vor der Veröffentlichung über die alten Git-Commits: Sie enthalten
   interne Arbeitsumgebungsangaben, die im aktuellen Stand entfernt wurden.
   GitHub Actions kann beim Öffentlichmachen außerdem alte Logs und
   Artefakte sichtbar machen. Die automatische Musterprüfung ist dokumentiert,
   garantiert aber nicht, dass Bilder oder alle denkbaren Geheimnisse erkannt
   wurden. Siehe [Release-Checkliste](releasing.md).
   Die betroffenen früheren Änderungen stehen in `AGENTS.md`, `STATE.md` und
   `docs/server-test-installation.md`. Gib historische Dateiinhalte nicht
   ungeprüft öffentlich weiter.
4. Eine nachträgliche Bereinigung der Git-Historie ändert Commit-IDs und kann
   bestehende Klone und Pull Requests beeinflussen. Führe keinen Force-Push
   oder keine Löschung aus, bevor Vorgehen und Sicherung ausdrücklich geprüft
   und freigegeben wurden. Das Projekt bleibt bis zu dieser Entscheidung privat.
5. Wenn alles geprüft ist und der Eigentümer den Merge freigibt, den Entwurf
   für Review freigeben und nach `main` mergen. Erst danach zeigt GitHub die
   aktuelle README und Community-Dateien auf dem Standardbranch.

## 2. Vertrauliche Sicherheitsmeldungen einschalten

1. Öffne im Repository **Settings** → **Advanced Security** unter
   **Security and quality**.
2. Aktiviere **Private vulnerability reporting**. Bei manchen Konten ist die
   Einstellung erst für ein öffentliches Repository verfügbar. Ist sie noch
   nicht sichtbar, muss ein verifizierter vertraulicher Kontakt vor der
   Veröffentlichung feststehen und die GitHub-Funktion unmittelbar nach der
   Freigabe aktiviert werden. Keinen unbestätigten Kontakt erfinden.
3. Öffne **Security** → **Advisories**. Dort sollte nach Aktivierung für
   meldende Personen **Report a vulnerability** verfügbar sein. Prüfe die
   Ansicht gegebenenfalls mit einem zweiten Konto; zum Melden kann eine
   Anmeldung erforderlich sein. Sende keine echte Testmeldung mit Zugangsdaten.
4. Die vorbereitete Datei `.github/VULNERABILITY_REPORT.yml` beschreibt das
   Formular, sobald sie auf dem Standardbranch liegt und GitHub private
   Meldungen aktiviert sind. Sie aktiviert die Funktion nicht selbst.

Weitere Hinweise stehen in der offiziellen
[GitHub-Anleitung](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository).

## 3. `main` schützen

Öffne **Settings** → **Branches** → **Add branch protection rule** und
verwende `main` als Branch-Pattern. Verlange Pull Requests und erfolgreiche
Statusprüfungen; wähle die tatsächlichen Namen aus einem abgeschlossenen
CI-Lauf, insbesondere Backend, Frontend, Browser, Container und Security.
Lass Force-Pushes und Branch-Löschung deaktiviert. Falls du alleiniger
Maintainer bist, verlange keine zweite Genehmigung, die du selbst nicht geben
kannst. Zusätzliche Organisations-Rulesets müssen gesondert geprüft werden.

Die Verfügbarkeit hängt vom GitHub-Tarif und der Sichtbarkeit ab. Bei GitHub
Free für persönliche Konten sind geschützte Branches für öffentliche
Repositories verfügbar; falls die Option privat fehlt, richte sie nach der
öffentlichen Freigabe ein. Aktiviere keine kostenpflichtigen Funktionen ohne
bewusste Entscheidung. GitHub deaktiviert bei einer Umstellung von privat auf
öffentlich bestehende **Push-Rulesets**; prüfe deshalb alle Regeln danach erneut.
Siehe [GitHub: geschützte Branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
und [Sichtbarkeit ändern](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility).

Prüfe unter **Settings** → **Advanced Security** zusätzlich, ob Dependency
Alerts, Secret Scanning und Push Protection für dein Konto verfügbar und
aktiviert sind. Die bereits laufenden CI-Scans ersetzen diese Einstellungen
nicht und beweisen nicht, dass die gesamte Historie frei von Geheimnissen ist.
