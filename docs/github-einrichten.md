# GitHub für das öffentliche Projekt einrichten

Diese Schritte sind für die Eigentümerin oder den Eigentümer des Repositories.
Eine GitHub-App mit Zugriff auf Code kann diese administrativen Einstellungen
nicht automatisch setzen. Auf dem Smartphone kann es helfen, die
Desktop-Ansicht des Browsers zu aktivieren. Je nach GitHub-Ansicht können
Menübezeichnungen leicht abweichen.

## 1. Historie und Pull Requests prüfen

1. Öffne [VulnRelay auf GitHub](https://github.com/LuPetro/vulnrelay) und
   melde dich als Eigentümer an. Das Repository ist öffentlich; `main` ist
   der Standardbranch.
2. Der [erste Pull Request](https://github.com/LuPetro/vulnrelay/pull/1) ist
   bereits nach `main` gemergt. Prüfe auch für weitere Änderungen die CI- und
   Security-Checks, bevor du sie über einen Pull Request übernimmst.
3. Alte Git-Commits enthalten interne Arbeitsumgebungsangaben, die im aktuellen
   Stand entfernt wurden. Auch GitHub-Actions-Logs und Artefakte sind jetzt
   öffentlich sichtbar. Die automatische Musterprüfung ist dokumentiert,
   garantiert aber nicht, dass Bilder oder alle denkbaren Geheimnisse erkannt
   wurden. Siehe [Release-Checkliste](releasing.md).
   Die betroffenen früheren Änderungen stehen in `AGENTS.md`, `STATE.md` und
   `docs/server-test-installation.md`. Falls dort oder an anderer Stelle echte
   Geheimnisse entdeckt werden, diese umgehend widerrufen oder rotieren.
4. Eine nachträgliche Bereinigung der Git-Historie ändert Commit-IDs und kann
   bestehende Klone und Pull Requests beeinflussen. Führe keinen Force-Push
   oder keine Löschung aus, bevor Vorgehen und Sicherung ausdrücklich geprüft
   und freigegeben wurden. Durch die bereits erfolgte Veröffentlichung können
   Kopien der bisherigen Historie bereits außerhalb des Repositories existieren.

## 2. Vertrauliche Sicherheitsmeldungen einschalten

1. Öffne im Repository **Settings** → **Advanced Security** unter
   **Security and quality**.
2. Prüfe, dass **Private vulnerability reporting** aktiviert ist.
3. Unter **Security** → **Advisories** ist **Report a vulnerability** auf
   der öffentlichen Seite sichtbar. Prüfe den Meldeablauf gegebenenfalls mit
   einem zweiten Konto; zum Melden kann eine Anmeldung erforderlich sein. Ein
   tatsächliches Absenden wurde bisher nicht getestet. Sende keine echte
   Testmeldung mit Zugangsdaten.
4. Die Datei `.github/VULNERABILITY_REPORT.yml` auf dem Standardbranch
   beschreibt das Formular. Sie aktiviert die GitHub-Funktion nicht selbst.

Weitere Hinweise stehen in der offiziellen
[GitHub-Anleitung](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository).

## 3. `main` schützen

GitHub zeigt `main` als geschützt an. Die genauen Regeln konnten durch die
verbundene Integration nicht ausgelesen werden. Prüfe sie unter **Settings** →
**Branches**; falls du eine neue klassische Regel anlegst, verwende `main` als
Branch-Pattern. Verlange Pull Requests und erfolgreiche Statusprüfungen; wähle
die tatsächlichen Namen aus einem abgeschlossenen CI-Lauf, insbesondere
Backend, Frontend, Browser, Container und Security.
Lass Force-Pushes und Branch-Löschung deaktiviert. Falls du alleiniger
Maintainer bist, verlange keine zweite Genehmigung, die du selbst nicht geben
kannst. Zusätzliche Organisations-Rulesets müssen gesondert geprüft werden.

Die Verfügbarkeit hängt vom GitHub-Tarif und der Sichtbarkeit ab. Bei GitHub
Free für persönliche Konten sind geschützte Branches für öffentliche
Repositories verfügbar. Aktiviere keine kostenpflichtigen Funktionen ohne
bewusste Entscheidung. GitHub deaktiviert bei einer Umstellung von privat auf
öffentlich bestehende **Push-Rulesets**; prüfe deshalb alle Regeln nach einer
solchen Änderung erneut.
Siehe [GitHub: geschützte Branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
und [Sichtbarkeit ändern](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility).

Prüfe unter **Settings** → **Advanced Security** zusätzlich, ob Dependency
Alerts, Secret Scanning und Push Protection für dein Konto verfügbar und
aktiviert sind. Die bereits laufenden CI-Scans ersetzen diese Einstellungen
nicht und beweisen nicht, dass die gesamte Historie frei von Geheimnissen ist.
