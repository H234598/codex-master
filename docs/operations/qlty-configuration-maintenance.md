---
priority: niedrig
---

# Qlty-Konfigurationspflege

Die zuständige Königin prüft die repositorylokale Qlty-Konfiguration bei der
ersten aktiven Arbeit oder Übernahme. Sie kann einen vollständigen, aktuell
gültigen Nachweis übernehmen, nachdem sie ihn mit dem tatsächlichen
Repository- und Konfigurationsstand abgeglichen hat. Ein Sessionwechsel allein
verlangt keine erneute Erstprüfung.

Bei aktiver Arbeit ist die nächste vollständige Prüfung spätestens
30 Kalendertage nach dem letzten vollständigen Abschluss fällig. Ein inaktives
Repository wird dafür nicht gestartet. Bei Wiederaufnahme holt die Königin
eine fällige Prüfung nach. Änderungen an Sprachen, Frameworks, Build, CI,
Qlty-Konfigurationsformat oder Plugins sowie konkrete Konfigurationsfehler
verlangen eine frühere Sichtung. Eine Sichtung ändert nur, was tatsächlich
nötig ist.

## Umfang und Nachweis

Prüfe `.qlty/qlty.toml`, zugehörige Plugin-Konfigurationen und Ignore-Dateien
gemeinsam. Vergleiche Dateiglobs, tatsächliche Pfade, Paket- und Sprachkontexte,
Abhängigkeiten, Formatter und Ausnahmen mit der Repositorystruktur und den
bestehenden Projektstandards. Bewerte Sicherheits-, CI-, Container- und
IaC-Prüfer jeweils gesondert; sie sind nicht allein wegen einer fehlenden
Anwendungssprache unpassend. Viele Findings rechtfertigen keine Deaktivierung.
Ein falscher MyPy-Pfad wird korrigiert, statt den Prüfer abzuschalten.

Der vollständige fortlaufende Nachweis liegt unter
`Projekte/<repo>/Berichte/Qlty-Konfigurationspflege.md` im Default-Vault
`/home/teladi/Dokumente/Obsidian_Vaults/Teladi_Programming`. Er enthält:

- Das Datum des vollständigen Abschlusses und den nächsten Termin.
- Den gebundenen Repository-, CLI- und Konfigurationsstand einschließlich
  Plugin-Konfigurationen und Ignore-Dateien.
- Die aktivierten und deaktivierten Plugins mit nachvollziehbaren Gründen.
- Die tatsächlichen Änderungen oder die Feststellung, dass keine nötig waren.
- Die ausgeführten Checks mit Befehlen, Exitcodes, Ergebnissen und
  Quellenbindungen.
- Bei geänderten Konfigurationen den Status und die Bestätigung des
  unabhängigen Reviews.

Nur eine vollständige Prüfung setzt den nächsten Termin fort. Eine vollständige
Prüfung ohne Änderung zählt ebenfalls. Bei Konfigurationsänderungen bleibt der
Abschluss bis zur Reviewbestätigung offen. Die Königin führt diesen Ablauf;
der Dokumentnachweis erfordert keine periodische Zustandsmaschine, automatische
Zeit- oder Startsperre, globale Allowlist-Registry und keinen neuen Dienst oder
Timer. Der vorhandene CLI-Upgrade-Timer bleibt unverändert.

## Unabhängige Prüfung geänderter Konfigurationen

Nur tatsächlich geänderte Qlty-, Plugin- oder Ignore-Konfigurationen erhalten
dieses zusätzliche Review. Eine Nichtautorin prüft den zusammenhängenden Diff
gemeinsam mit der Repositorystruktur, den Begründungen und den QA-Ergebnissen.
Sie beurteilt insbesondere verlorene Abdeckung, verdeckte Findings, falsche
Pfade und Formatterkonflikte. Einzelreviews je Plugin sind nicht erforderlich.

Verwende das höchste freigegebene verfügbare Reviewmodell mit der höchsten
zulässigen unterstützten Reasoning-Stufe. Auftrag, Bestätigung und Ergebnis
binden die konkrete Modellkennung und die tatsächlich verwendete Reasoning-Stufe
wahrheitsgemäß. Bei fehlender Verfügbarkeit bleibt das Review offen; eine stille
Herabstufung ist unzulässig. Unabhängig mögliche Arbeit läuft weiter. Eine
gezielte Nachprüfung beschränkt sich auf konkrete Korrekturen. Ohne Änderung
ist dieses Zusatzreview nicht nötig.

## Repositorypassendes Pluginset

Ein vollständiger lokaler Check verwendet alle für das Repository benötigten
aktivierten Plugins. Es gibt keine feste Katalogzahl. Der Qualitätshelper bindet
weiterhin den gesamten unterstützten Katalog einschließlich versteckter
Definitionen; das wirksame aktive Set darf eine gültige nichtleere Teilmenge
sein. Leere Sets, unbekannte Namen, doppelte Einträge und die bisherigen
Pluginrestriktionen bleiben ungültig.

Die mutierende Formatphase verwendet ausschließlich aktive Formatter aus
`ruff`, `prettier` und `shfmt` auf den einzeln freigegebenen
`--format-path`-Dateien.
Ohne solche aktiven Formatter wird sie als `not_applicable` dokumentiert und
kein Formatkommando ausgeführt. Andere aktive Formatter werden weiterhin vom
ungefilterten vollständigen Check als Validatoren erfasst. Außenbytes bleiben
geschützt. Der Helper behält seine Vorher-/Nachherbindungen für semantische
Konfiguration, Pluginset und CLI sowie seine Driftprüfungen bei.

Die bestehenden `work`-, `test`- und `freeze`-Guards werden mit ihrer eigenen
Owner- und Guardkennung regulär beendet. Fremde Guards werden nicht entfernt.
Vor jedem Commit veranlasst die Königin den frischen vollständigen
`precommit`-Lauf über den geprüften gemeinsamen Qualitätsowner
`<UID-Home>/the_hive/scripts/the-hive-qlty-maintenance`. Er führt nach der
begrenzten Formatierung `metrics --all`, `smells --all --no-snippets` und
`check --all --no-fix --no-cache --sarif --print-errors` aus. Ad-hoc-Filter oder
Skip-Flags ersetzen keinen vollständigen Check. SARIF, native Aufrufnachweise,
echte Exitcodes und die Abdeckung der tatsächlichen Commitdateien bleiben
verpflichtend. Historische Befunde ersetzen keinen frischen Lauf.

Bevor produktive Königinnen Pluginsets verkleinern, muss der geprüfte Helper
mit Teilmengenunterstützung auf dem unterstützten Installationspfad verfügbar
sein. Ein Sourcecheckout allein belegt keine installierte Runtime. Diese
Anleitung erteilt keine Installations-, Root-, Reload- oder Cutoverautorität.

## Begründung für dieses Repository

Der gepflegte Stand enthält Python, GJS/JavaScript, Shell, Markdown, YAML,
JSON und native C-Helfer. Die folgenden Gruppen bleiben aktiviert:

- **Python:** `ruff`, `black`, `flake8`, `mypy`, `radarlint-python`, `bandit`.
  Pythonquellen, Tests und der extensionlose Qualitätshelper benötigen Lint-,
  Typ-, Format- und Sicherheitsprüfungen.
- **JavaScript und strukturierte Dateien:** `eslint`, `oxc`, `biome`,
  `radarlint-js`, `prettier`, `yamllint`.
  Das GJS-Applet, der Node-Vertragstest sowie YAML- und JSON-Dateien sind
  tatsächliche Quellen. Bestehende GJS-Regeln bleiben erhalten.
- **Shell:** `shellcheck`, `shfmt`.
  Installer und Wrapper enthalten Shellcode.
- **Dokumentation:** `markdownlint`, `vale`, `prettier`.
  Markdown wird geprüft; die vorhandenen Vale-Regeln und die eng begrenzten
  Prettier-Ausnahmen für kanonische JSON-Bytes bleiben erhalten.
- **Sicherheit und Regeln:** `ast-grep`, `semgrep`, `gitleaks`, `trufflehog`,
  `trivy`, `ripgrep`.
  Die vorhandenen Quellregeln und generischen Sicherheitsprüfungen bleiben
  unabhängig von Sprachformatterentscheidungen aktiv. Die generischen Scans
  erfassen auch native Quelldateien.
- **CI und IaC:** `actionlint`, `zizmor`, `checkov`.
  GitHub Actions ist vorhanden; Checkov kann den tatsächlichen Workflow prüfen.
  Fehlende Container- oder Terraformdateien rechtfertigen hier keine
  Abschaltung der CI-Prüfer.

Die übrigen Definitionen bleiben Teil des gebundenen Qlty-Katalogs, sind hier
jedoch nicht aktiviert:

- `brakeman`, `haml-lint`, `reek`, `rubocop`, `ruby-stree`, `standardrb`,
  `coffeelint`, `prisma`, `sqlfluff`, `stylelint`:
  Es gibt keine Ruby-, Haml-, CoffeeScript-, Prisma-, SQL-, CSS- oder
  Sass-Quelldateien.
- `gofmt`, `golangci-lint`, `radarlint-go`, `clippy`, `rustfmt`:
  Es gibt keine Go- oder Rustquellen und keine zugehörigen Projekte. Der
  Sicherheitsprüfer `golangci-lint` wurde ausdrücklich auf diesen fehlenden
  Kontext geprüft.
- `checkstyle`, `google-java-format`, `pmd`, `radarlint`, `radarlint-java`,
  `ktlint`, `radarlint-kotlin`, `radarlint-scala`:
  Es gibt keine Java-, Kotlin-, Scala- oder Apexprojekte.
- `php-codesniffer`, `php-cs-fixer`, `phpstan`, `radarlint-php`,
  `radarlint-ruby`:
  Es gibt keine PHP- oder Rubyquellen.
- `stringslint`, `swiftformat`, `swiftlint`:
  Es gibt keine Swift-, Objective-C-, Xcode- oder Stringsprojekte.
- `dockerfmt`, `hadolint`, `radarlint-iac`, `terraform`, `tflint`,
  `kube-linter`:
  Die Container-, Terraform- und Kubernetesrelevanz wurde gesondert geprüft.
  Versionierte Produktdateien dieser Art fehlen; normale YAML-Regeln und
  CI-Prüfer bleiben aktiv. Die bisherigen Kubernetes-Ausnahmen für gewöhnliche
  YAML-Dateien entfallen mit dem unpassenden Plugin.
- `knip`, `tsc`:
  Es gibt weder TypeScriptquellen noch `package.json` oder `tsconfig.json`.
  Das GJS-Applet und der eigenständige Node-Test sind kein
  TypeScript-Paketkontext. Die bisherige feste `tsc`-Version wird entfernt.
- `redocly`, `spectral`:
  Es gibt keine OpenAPI-, AsyncAPI- oder Arazzo-Spezifikation.
- `dotenv-linter`, `editorconfig-checker`:
  Es gibt keine Dotenvdateien und keinen `.editorconfig`-Standard. Vorhandene
  Formatierungsstandards werden durch die aktiven Sprachformatter geprüft.
- `osv-scanner`:
  Es gibt keine vom vorhandenen Lockfile-Treiber adressierte
  Abhängigkeits-Lockdatei.
  Die Repository-Sicherheitsprüfungen einschließlich Trivy bleiben aktiv.

Die bisherigen Standardsprachglobs und Formatterrollen bleiben erhalten.
Die 20 extensionlosen Pythonscripts und elf extensionlosen Shellscripts werden
zusätzlich über ihre tatsächlichen Repositorypfade zugeordnet. Der echte
Qlty-Ziellauf hat gezeigt, dass die vorhandenen `interpreters`-Metadaten allein
diese Dateien nicht auswählen. Die drei versionierten extensionlosen
Ignore-Dateien sind keine Python- oder Shellquellen.

Der bisherige `ALL`-Glob `*.*` erreicht keine endungslosen Namen. Er bleibt
erhalten und wird durch `*` ergänzt, damit die allgemeinen Geheimnisscanner
auch die tatsächlichen extensionlosen Quellen auswählen. Das erweitert die
Abdeckung; es entsteht keine neue Ausnahme.

Der globale
Defaultausschluss `**/config/**` wird entfernt, weil `systemd/config/`
versionierte produktive Konfiguration enthält. Generierte Build-, Cache- und
Distributionsartefakte bleiben nach ihren bisherigen engen Zwecken ausgenommen.
Es werden keine Findings durch neue pauschale Ausnahmen verborgen.

Der aktuell unterstützte Qlty-Katalog enthält keinen speziellen C-Prüfer.
Gitleaks und Trufflehog erreichen die fünf `.c`- und zwei `.h`-Dateien als
allgemeine Geheimnisscanner; ein gezielter echter Lauf ist über ihre nativen
Aufrufnachweise belegt. Das ist keine Syntax-, Typ-, Speicher- oder vollständige
Sicherheitsanalyse von C. Die vorhandenen Ast-grep- und Semgrep-Regeln sind
weiterhin auf Python und JavaScript begrenzt. Die nativen Compiler- und
Consumer-Vertragstests behalten deshalb ihre eigene Verantwortung; ein grüner
Geheimnisscan ersetzt diese Tests nicht.

MyPy bleibt aktiviert. `src/the_hive/selection.py` existiert tatsächlich neben
dem gleichnamigen Paket `src/the_hive/selection/`. Der normale Dateitreiber
prüft beide Pfade in getrennten Einzelaufrufen. Der frühere globale
MyPy-Ausschluss des Moduls und der zusätzliche `legacy_selection`-Literaltreiber
entfallen: Der Ausschluss entfernte das Modul aus Qltys Dateiauswahl, sodass
die Rohdiagnosen des Literallaufs nicht in dessen SARIF-Ausgabe gelangten.
Ein erfolgreicher Toolprozess allein belegt deshalb keine vollständige
Befundübernahme. Die vorhandene MyPy-JSON-Ausgabe und ihr Qlty-Parser bleiben
unverändert. Eine echte Regression prüft gleichnamiges Modul und Paket sowie
die vollständige Übernahme ihrer Rohbefunde in SARIF. Es wird kein Typ- oder
Importfilter ergänzt.

## MyPy-Aufrufe und Bandit-Testassertions

Die korrekt zugeordneten extensionlosen Pythonscripts sind eigenständige
Programme. MyPy 1.19.1 benennt sie standardmäßig als `__main__`; mehrere davon
in einem Batch verhindern deshalb die weitere Typprüfung. Die dokumentierte
Option `--scripts-are-modules` reicht hier ebenfalls nicht aus, weil
`bin/the-hive-home-broker` und `systemd/libexec/the-hive-home-broker` denselben
Basenamen haben. Der vorhandene MyPy-Dateitreiber verwendet deshalb
`batch = false`. Er prüft weiterhin jede Datei, ohne Script- oder
Plugin-Ausnahme und ohne zusätzliche Treiber- oder Wrapperlogik. Die
ursprüngliche Modulbenennung bleibt erhalten; auch das bisher getrennt
behandelte Auswahlmodul wird vom normalen Dateitreiber erfasst.
[MyPy 1.19.1](https://github.com/python/mypy/blob/v1.19.1/docs/source/command_line.rst),
[Qlty-Batchsteuerung](https://github.com/qltysh/qlty/blob/c3c7ceb/qlty-check/src/planner/target_batcher.rs).

Der Dateitreiber läuft vom Repositoryroot und setzt `MYPYPATH=src`. Damit
bleiben Anwendungsimporte beim einzelnen Script typisiert, auch wenn im
selben Aufruf keine Anwendungsdatei mehr als zusätzliches Suchpfadindiz
enthalten ist. Eine private Regression prüft typisierte Aufrufargumente und
den unveränderten qualifizierten Namen eines normalen Anwendungsmoduls.
Es werden weder Namespaceoptionen noch zusätzliche Importunterdrückungen
eingeführt. `--no-incremental` verhindert außerdem, dass MyPy bei bytegleichen
Scripts alte Diagnosepfade aus einem fremden `__main__`-Cache übernimmt.
Die Einzeldateiprüfung erzeugt mehr MyPy-Prozesse und native
Aufrufnachweise als die bisherigen Batches mit bis zu 64 Dateien; dadurch
kann der vollständige Lauf länger dauern; zusätzlich wird der interne
inkrementelle MyPy-Cache nicht wiederverwendet. Sie wird nicht als
Laufzeitgewinn oder als verschwundener Typbefund dargestellt.

Qlty 0.663.0 begrenzt in seinem fest gebundenen Executor die Ausgabe auf
500 Befunde je Datei. Die Grenze ist in diesem CLI-Stand eine Konstante und
keine unterstützte Qlty- oder Plugin-Konfigurationsoption. Ein geteilter
Bandit-Batch hebt die Grenze je Datei nicht auf. Der Qualitätsconsumer wird
deshalb nicht geändert und eine gekappte Ausgabe gilt weiterhin nicht als
vollständiger Abschluss.
[Qlty-Executor](https://github.com/qltysh/qlty/blob/c3c7ceb/qlty-check/src/executor.rs).

In `tests/test_runtime_lifecycle_service.py` sind die 675 B101-Befunde
Assertions für pytest-Erwartungen und private Testhelfer. Die offizielle
Bandit-Option `assert_used.skips` nimmt in `.bandit.yaml` ausschließlich B101
für genau diese Datei in ihren beiden relativen Pfadschreibweisen aus.
Die übrigen Bandit-Regeln bleiben auch dort aktiv. Insbesondere sind die
20 anderen Befunde dieser Datei weiterhin vollständig zu erfassen. B101
bleibt für Produktionscode und für andere Tests aktiv; private negative
Fixtures belegen dies zusätzlich für eine Produktionsdatei mit demselben
Basenamen und für andere Testbefunde. Es gibt weder eine globale
B101-Deaktivierung noch einen Ausschluss des Testverzeichnisses.
[Bandit 1.9.2: assert_used](https://bandit.readthedocs.io/en/1.9.2/plugins/b101_assert_used.html).

## Trivy und gleichzeitig geschriebene Caches

Der Trivy-Konfigurationstreiber prüft das Literalziel `.` mit seinem eigenen
Dateibaumdurchlauf. Qltys Dateiauswahl und Gitignore verhindern diesen
internen Durchlauf nicht. Ein vollständiger Lauf scheiterte beim `lstat`
einer inzwischen entfernten temporären Datei in `.mypy_cache/3.11/`.
Deshalb überspringt ausschließlich dieser Treiber mit der offiziellen
Option `--skip-dirs .mypy_cache` den nachweislich generierten, bereits von
Git ignorierten MyPy-Cache. Die MyPy-Prüfung selbst bleibt unverändert.
Eine private echte Trivy-Regression vergleicht identische unsichere
Dockerfiles: Das Cacheexemplar wird ausgelassen, die Exemplare unter
`deployment/` und `.qlty/active/` behalten ihre IaC-Befunde.
[Trivy 0.69: Dateiauswahl](https://trivy.dev/docs/v0.69/guide/configuration/skipping/).

Die Bestandsaufnahme fand außerdem `.ruff_cache`, `.pytest_cache` sowie
die unversionierten Qlty-Ausgaben unter `.qlty/out`, `.qlty/logs`,
`.qlty/results` und `.qlty/plugin_cachedir`. Für diese Pfade ist kein
entsprechender Fehler belegt; sie erhalten keine zusätzliche Ausnahme.
`.git` ist in diesem Worktree eine Verweisdatei. Der getrackte Inhalt von
`.qlty/`, einschließlich `qlty.toml` und `ast-grep/no-eval.yml`, bleibt
erreichbar; es gibt keinen pauschalen Ausschluss dieses Verzeichnisses.

Die erfolgreichen vorherigen Trivy-Konfigurationsläufe meldeten jeweils
`Detected config files num=0`. Das versionierte Repository enthält derzeit
keine von diesem Treiber erkannte IaC und keine CloudFront-Ressource;
allgemeine YAML-Dateien und GitHub Actions sind kein solcher Nachweis.
Trivy bleibt insbesondere für die separate Geheimnisprüfung aktiviert.
Die Warnung zum Modul `policies/aws/cloudfront/enable_logging.rego`
(`AVD-AWS-0010`) betrifft die CloudFront-Zugriffsprotokollierung und verlangt
mindestens Trivy 0.72.0. Sie ist vom Cachefehler unabhängig und betrifft
derzeit keine Repositoryressource. Der offiziell verfügbare Stand 0.76.1
erfüllt diese Versionsuntergrenze; ein Versionswechsel gehört deshalb
aber nicht zum Cachefix. Es wird keine Versionswarnung unterdrückt.
Bei neuen IaC-Ressourcen ist die Relevanz samt Pluginversion erneut zu
prüfen.
[CloudFront-Regel](https://github.com/aquasecurity/trivy-checks/blob/main/checks/cloud/aws/cloudfront/enable_logging.rego),
[offizieller Trivy-Release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1).
