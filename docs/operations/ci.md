# The Hive CI

`.github/workflows/ci.yml` ist die eingecheckte GitHub-Actions-Definition. Sie
setzt `contents: read`, pinnt die verwendeten externen Actions auf vollständige
Commit-SHAs und enthält Syntax-, Ruff-, Test-, Manpage-, Whitespace-,
Wrapper- und Pool-Checks. Der Workflow installiert seine Prüfabhängigkeiten
auf dem Runner; diese Dokumentation führt keine davon aus.

## Bekannter Blocker

Der Manifest-Validierungsschritt ist im aktuellen Quellstand widersprüchlich:
`.codex-plugin/plugin.json` und `.app.json` tragen `the-hive`, während der
Workflow noch die historischen Schlüssel `codex-master` erwartet. Damit ist
eine grüne CI-Aussage nicht belastbar. Ein tatsächlich letzter Remote-Lauf
wurde nicht abgefragt und bleibt unbekannt.

Auch weitere historische Zeichenketten in Workflow, Tests oder technischen
Zustandsverträgen sind keine Produktbezeichnung. Aktive Produktdokumentation
verwendet The Hive; die technische Bereinigung dieses CI-Konflikts ist ein
separates Produkt-/CI-Paket und nicht Gegenstand dieser Dokumentationsänderung.

## Prüfgrenze

Für diese Dokumentation sind nur fokussierte Markdown-, Link-, Pfad- und
Beispielprüfungen angemessen. Lokale Erfolgsmeldungen oder eine
Quelltextlektüre ersetzen keinen GitHub-Runner-Lauf.
