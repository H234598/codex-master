<!-- codex-master-common-policy:{"generation":10,"schema_version":1} -->
# Common Hive context

This file is materialized and maintained by The Hive (masterjet). It is the
shared, generic context for every managed bee. The class profile referenced
below is separate and is the only class-specific policy active in this home.

## Hive-wide replacement and cutover policy

Wenn eine saubere Zielarchitektur möglich ist, keine fortlebende
Übergangslösung bauen. Zielpfad neu bauen und testen; Zustand parallel
migrieren, wo sicher; atomar umschalten; Altpfad abschneiden und entfernen.
Wo Parallelbetrieb unmöglich ist, sichtbaren Ausfall akzeptieren und aus
kanonischem Profil, Policy, Credentials und ResumeCapsule neu bauen oder
starten. Einmalige Migration ist erlaubt, bleibt aber kein Reader, Writer,
Router, Fallback oder Kompatibilitätspfad.

## Hive-wide test policy

Jede produktive Funktion braucht mindestens einen eindeutig zugeordneten,
ausführbaren Test. Bei parametrisierten Tests oder Testmatrizen muss jede
Funktion einen eigenen Fall besitzen. Bloße indirekte Ausführung ohne eine den
Funktionsvertrag prüfende Assertion reicht nicht.

Beim Bauen gilt zuerst: so wenig Testcode, Fixtures, Mocks und
Test-Infrastruktur wie möglich, aber genug für den echten Funktionsvertrag.
Tests müssen tatsächlich ausgeführt werden. Manuelle Prüfung oder bloßes Lesen
ersetzt keinen Testlauf.

Die Regel minimiert Bauarbeit und die Zahl ausgeführter Tests. Sie erlaubt
niemals, einen erforderlichen Testlauf durch Eigenprüfung zu ersetzen.

Beim Auswählen und Ausführen gilt: so wenig Tests wie möglich, so viele wie
nötig. Zuerst den kleinstmöglichen gezielten Test für die Funktion ausführen.
Danach nur um betroffene Grenz-, Integrations- und Regressionstests erweitern.
Ein vorhandenes grünes Testergebnis darf nur bei unveränderten relevanten Inputs
und noch gültigem Evidence-Reuse-Fenster wiederverwendet werden. Andernfalls den
Test neu ausführen. Vorgeschriebene Voll- und Release-Gates bleiben verbindlich
und werden einmal am passenden Gate ausgeführt.

## Public documentation OPSEC

For all documentation work, treat published documentation as public and
machine-indexable by default. Do not include personal identifiers, secrets or
credentials, internal resource identifiers, private network addresses or local
absolute paths, or raw logs, stack traces, or screenshots. Use portable
placeholders only. Keep internal operational documentation separate; when an
operational identifier is truly necessary, confine it to an explicitly
access-restricted document. Secrets are never permitted. Apply the detailed
rule at `docs/development.md#public-documentation-opsec`.

## Obsidian Annotation Marker

When working on an Obsidian plan or guide, look for the matching Annotation
Marker sidecar under `.obsidian/plugins/annotation-marker/annotations/` and
evaluate its markers before changing the source document. The sidecar name
encodes the vault-relative source path with `&.` separators.

The numeric suffix in `--annotation-*-colorN` is authoritative. The visible
color alone is not reliable. `data-annotation-note` contains the user's note;
use `data-annotation-id` to distinguish markers with the same text or line.

- `color1` (red): no, danger, do not implement this way. Stop, explain, and
  correct the affected point.
- `color2` (blue): an architectural decision by the user. It replaces a
  conflicting draft.
- `color3` (yellow): a question. Answer it; do not treat it as approval.
- `color4` (green): agreement and approval to implement.
- `color5` (purple): an extensive, understandable explanation is required.
- `color6` (dark blue or orange): the user is uncertain and needs consequences,
  alternatives, trade-offs, and a reasoned recommendation; do not silently
  decide for them.

Annotations are working instructions, not decoration. Annotation-Marker-Sidecars
under `.obsidian/plugins/annotation-marker/annotations/` are exclusively
read-only input sources. When responding to an annotation or revising a
document, write the response, `(A)` link, explanation, decision, status, and
every other change exclusively to the vault-relative original Markdown file.
Never write, create, delete, rewrite, or append sidecars. If a sidecar and its
original conflict, leave both unchanged and report
`annotation_sidecar_original_conflict`.

## Obsidian and local file links

Keep vault-internal links and clickable local response links distinct. Resolve
the target before emitting either form.

- In Obsidian documents, prefer an unencoded vault-relative wikilink:
  `[[Projekte/PVE4/Datei mit Leerzeichen|Text]]`.
- Where an Obsidian document requires a normal Markdown link, keep the
  vault-relative path unencoded and enclose a target containing spaces in angle
  brackets: `[Text](<Projekte/PVE4/Datei mit Leerzeichen.md#Abschnitt>)`.
- In a Codex response, link a real local file with its raw absolute path and an
  optional line number inside angle brackets:
  `[Text](</absoluter/Pfad/Datei mit Leerzeichen.md:42>)`.
- Never replace spaces in local filesystem link targets with `%20`. Never use
  `file://` or `vscode://`. These restrictions apply to local file links, not
  external HTTP(S) URLs.

## Context and scope

Follow the active class profile in this home. Do not load another bee's class
profile or copy class-specific instructions from another home. The Hive may
replace this file and the active class file on a safe start or class change.
Running sessions are not modified in place.

## Dateisuchen außerhalb benannter pCloud-Namensräume

Jeder normale `rg`-Lauf enthält alle vier exakten Globs:

- `--glob '!pCloudDrive/**'`
- `--glob '!pCloud/**'`
- `--glob '!**/pCloudDrive/**'`
- `--glob '!**/pCloud/**'`

`/home/teladi/pCloud` darf nicht als Suchwurzel übergeben werden. Normales GNU
`grep` nicht verwenden: GNU grep kennt `--glob` nicht; stattdessen `rg`
verwenden. Explizite Suche im jeweils benannten pCloud-Namensraum ist die
einzige Ausnahme. Diese gemeinsame Regel wird für jede Klasse und jedes Home
beim Spawn und Resume mit diesem Common Hive context materialisiert.

## OpenAI-Account- und Context-Reset-Policy

Bei aktiver OpenAI-Arbeit so lange wie möglich und mindestens themenbezogen auf demselben OpenAI-Account bleiben, weil der Prompt-/Context-Cache accountgebunden ist. Wechsel nur bei hartem Auth-/Limit-/Capability-/Resource-Block oder abgeschlossenem Thema; kein opportunistischer Wechsel.

Automatisierte Context-/Session-Resets einschließlich daraus entstehender Accountrotation sind nur erlaubt, wenn ein frischer, reset-konsistenter Snapshot über alle Accounts zugleich belegt:

1. Account der zu resettenden Session hat weder nutzbares Wochen- noch Monatsrestlimit.
2. Jeder andere Account hat unter 10% Rest im jeweils zeitlich höchsten vorhandenen Abo-Fenster; Monat vor Woche.
3. Jeder andere Account, der noch positives Wochen-/Monatslimit und ein 5h-Fenster besitzt, hat dort kein nutzbares oder unter 5% Restguthaben.

Fehlende, stale, widersprüchliche oder nicht vergleichbare Daten blockieren automatische Aktion fail-closed. Account ohne Wochen-/Monatsfenster liefert keinen positiven Ersatz-Headroom. Natürlicher Usage-Window-Reset und explizite Administratoraktion sind ausgenommen. Wenn das Gate nicht erfüllt ist: Session erhalten/schlafen/resumen, nicht opportunistisch rotieren.

## Übergabe externer Markdownpläne

Wenn ein vollständiger Markdownplan außerhalb des eigenen Worktrees abgelegt
wird, muss die Instanz anschließend `bin/codex-master-publish-plan-path`
verwenden. Bei jeder Dokument-/Planübergabe darf die Instanz die
Zwischenablage weder automatisch lesen, entdecken, verwenden noch verändern;
ein bereits vorhandener Zwischenablageinhalt bleibt unverändert. Das Werkzeug
validiert die Datei und schreibt den validierten absoluten
Markdown-Dateipfad exakt auf stdout. Danach zeigt es eine variierende sichtbare
Desktop-Benachrichtigung, die den vollständigen absoluten Pfad enthalten muss.
Die Benachrichtigung darf keine Aussage über Kopieren oder das Ablegen in die
Zwischenablage enthalten. Die Regel gilt für Vaults, `/Baupläne!`, alle
anderen externen Dokumentpfade serverweit und für zukünftige Client-Bridges.

## Bidirektionale Abschnitts- und Annotation-Antworten in Obsidian

Jede direkte Antwort auf einen Dokumentabschnitt ist auch ohne Annotation
Marker bidirektional zu verlinken. Die Antwort enthält genau einen eindeutig
aufgelösten normalen Markdown-Link auf den primären Quellabschnitt oder seine
Überschrift. Der Quellabschnitt enthält genau einen Rückverweis auf das
konkrete Antwortziel und die konkrete Antwortüberschrift. Bei mehreren
Quellkapiteln sind vor jeder Mutation alle tatsächlich referenzierten
Quellüberschriften eindeutig aufzulösen. Der Antworttext enthält für jede
tatsächlich referenzierte Quellüberschrift genau einen normalen Markdown-Link.
Jeder jeweilige Quellabschnitt enthält genau einen idempotenten Rückverweis auf
dieselbe Antwort. Fehlt, ist mehrdeutig oder konfliktierend eine Quelle, wird
die gesamte Mehrquellenmutation fail-closed blockiert: weder Antwortkapitel
noch irgendein Rückverweis schreiben. Eine vorhandene Annotation-ID ist bei
einer reinen Abschnittsantwort ein optionaler zusätzlicher Anker; sie ist dafür
nicht erforderlich. Bei einer direkten Antwort auf eine Annotation bleibt die
Annotation-ID dagegen erforderlich; zusätzlich gelten die nachfolgenden
exakten Annotation-Regeln.

Vor jeder Dokumentmutation einer Abschnittsantwort sind Quelldokument,
Quellabschnitt, Quellüberschrift, Source-Link-Ziel, Antwortziel und
Antwortüberschrift eindeutig aufzulösen. Jede Auflösung muss genau einen
widerspruchsfreien Wert ergeben. Eine fehlende, mehrdeutige oder
widersprüchliche Auflösung erzwingt fail-closed: Es wird weder Antwortkapitel
noch Rückverweis geschrieben. Passender vorhandener Rückverweis und passender
vorhandener Antwortlink werden wiederverwendet. Ein konfliktierender
vorhandener Rückverweis oder Antwortlink ist ein Blocker; nie einen zweiten
Rückverweis oder Antwortlink schreiben. Vor jedem Retry erneut auflösen und
abgleichen.

Eine beantwortete Annotation erhält ein eigenes Kapitel am Dokumentende. Die
Antwortüberschrift muss exakt dieser Markdown-Form folgen:
`## <exakte Annotation-Überschrift ohne finale ID> — [<Annotation-ID>](<eindeutiger Link auf referenzierten Annotationsabschnitt oder dessen Überschrift>)`.
Die exakte Annotation-Überschrift steht ohne finale ID vor dem em dash `—`.
Eine Inline-Annotation verwendet die umgebende Markdown-Überschrift nur dann
unverändert als Basisteil der Antwortüberschrift, wenn sie weder einen
terminalen Annotation-Identifier noch einen konfliktierenden ID-Link enthält.
Andernfalls gilt fail-closed: keine Dokumentmutation; die Überschrift niemals
automatisch abschneiden, entfernen oder normalisieren. Die Antwortüberschrift
hängt ausschließlich den aktuellen verlinkten Annotation-Identifier am Ende an.
Die erforderliche Markdown-Selbstlink-Syntax ist ein normaler Markdown-Link.
Die sichtbare ID bleibt unverändert und exakt erhalten. Für den
Heading-Identifier gilt: kein Wikilink für den Heading-Identifier. Ziel zuerst
eindeutig auflösen;
der Markdown-Link muss eindeutig auf den referenzierten Annotationsabschnitt
oder dessen Überschrift zeigen. Antworten, Erklärungen, ADRs und Fragen
bleiben jeweils eigene Kapitel am Dokumentende und werden nicht zu einem
Sammelkapitel oder Inline-Text zusammengezogen.

Der Quellabschnitt erhält dafür genau eine idempotente Inline-Verknüpfung. Die
verlinkte Antwort auf eine Annotation steht direkt hinter der konkreten
Annotation. Sichtbar besteht sie exakt aus `(A)`; Beispiel:
`<Annotation> (A). Hier weiterer Text.` Die kanonische Markdown-Form des
sichtbaren Links ist `[(A)](<Antwortziel>#<Antwortueberschrift>)`. Genau ein
Leerzeichen zwischen Annotation und Link; Link vor nachfolgender
Interpunktion oder weiterem Text. Es gibt keine separate
`Beantwortung der Frage ...`-Zeile mehr. (A) ist nur der Rückverweis; die
vollständige Antwort bleibt als eigenes Kapitel am Dokumentende. Das
Antwortkapitel behält den eindeutigen normalen Markdown-Link zur Quellannotation
oder Quellüberschrift und die `data-annotation-id`.

Vor jeder Dokumentmutation sind Quellabschnitt, Source-Heading-Markdownziel,
Annotation-ID, Antwortziel und Antwortüberschrift eindeutig aufzulösen. Jede
Auflösung muss genau einen Wert ergeben. Sind Daten fehlend, mehrdeutig oder
konfliktierend, gilt fail-closed: Es wird weder die Quellzeile noch das
Antwortkapitel geschrieben. Ein passender vorhandener Rückverweis wird wiederverwendet.
Ein nichtpassender vorhandener Rückverweis ist ein Blocker,
nie eine zweite Zeile. Vor jedem Retry sind Annotation, Quellziel, Antwortziel
und Antwortüberschrift erneut gegen den vorhandenen Rückverweis zu prüfen.

Vor jeder Änderung einer Obsidian-Quelldatei als direkte Antwort auf eine
Annotation ist das passende Annotation Marker-Sidecar unter
`.obsidian/plugins/annotation-marker/annotations/` zu finden und auszuwerten.
Fehlt für die direkt beantwortete Annotation das passende Sidecar, wird die
Quelldatei nicht geändert. Die Regeln für `color1` bis `color6`,
`data-annotation-note` als User-Notiz und `data-annotation-id` als eindeutige
Marker-ID bleiben bindend; Marker und ihre Notizen werden erhalten.

<!-- hive-runtime-migration-policy-v1:begin {"source_digest":"sha256:90a0c560b9ea18708d64aee609a3c34c7e5f9b3f6e555de662434db164cf9e53","version":1} -->
## Hive Runtime- und Release-Migrationspolicy v1

Diese versionierte Policy ist technologie-neutral. `enforcement: machine` kennzeichnet einen verbindlichen, maschinenprüfbaren Laufzeit- oder Releasevertrag. Dieser Policy-Compiler erzwingt derzeit ausschließlich die kanonische Quelle, die normierten Maschinenverträge und ihre vollständige Projektion; ein Policy-Executor für die operative Durchsetzung dieser Verträge ist unbekannt und nicht implementiert. Daraus folgt keine Aussage über vorhandene Runtime-Mechanismen. `enforcement: governance` kennzeichnet einen verbindlichen menschlichen Prozess-Gate.

Kanonische Quelle: `src/the_hive/markdown/runtime-migration-policy-v1.json`.

### delivery-and-preflight

Getrennte Liefergegenstände und beobachtbare Vorprüfungen verhindern, dass Produktänderungen unter Zeitdruck zu unkontrollierten Runtime-Eingriffen werden.

Maschinenvertrag (nur Source-/Compiler-Durchsetzung): `{"cutover_preflight":"read_only_live","development_preflight":"read_only_live","feature_delivery":"separate","migration_budget":"separate_prerequisite","migration_delivery":"separate_prerequisite","scope_gate":"explicit"}`

- `separate-feature-and-migration-deliverables` (enforcement: governance): Eine kleine Feature-Änderung und eine Runtime- oder Installationsmigration werden als getrennte Liefergegenstände geplant, geprüft und freigegeben.
- `read-only-live-preflight-before-development-and-cutover` (enforcement: governance): Vor Entwicklungsbeginn und unmittelbar vor dem Cutover wird ein ausschließlich lesender Live-Preflight mit attestierter Ausgangslage durchgeführt; fehlende oder widersprüchliche Evidenz blockiert.
- `migration-budget-gate` (enforcement: governance): Eine unerwartete Migration wird ein eigenes Voraussetzungspaket; das ursprüngliche Feature darf seinen Umfang nicht still erweitern.
- `scope-multiplication-gate` (enforcement: governance): Jede Ausweitung auf weitere Hosts, Consumer, Datenklassen oder Migrationsschritte benötigt ein explizites Scope-Gate und darf nicht implizit vervielfacht werden.

### versioning-and-deterministic-execution

Explizite Versionen, gebundene Eingaben und reproduzierbare Abläufe machen Migrationen prüfbar und begrenzen TOCTOU- sowie Kompatibilitätsrisiken.

Maschinenvertrag (nur Source-/Compiler-Durchsetzung): `{"bundle":{"implicit_path_dependency":"deny","interactive_shell_dependency":"deny","worktree_dependency":"deny"},"compatibility":{"attested_predecessor_count":1,"current_version_required":true,"support_window_versions":2,"unbounded_legacy":"deny"},"downlevel":{"mode":"reject","offline_staged_path":"required"},"dry_run":{"actions":true,"bound_inputs":true,"cutover_rebind":"cas_fencing","digests":true,"rollback":true,"target_identity":true},"idempotence":"required","lifecycle_phases":["install","migrate","activate","rollback"],"migrator_edge":"runtime-vN-to-vN-plus-1","provenance":"attested_before_publish"}`

- `explicit-versioned-stepwise-migrators` (enforcement: machine): Jeder Online-Migrationsschritt ist explizit als runtime-vN→vN+1 versioniert; implizite Sprünge sind verboten.
- `bounded-compatibility-window` (enforcement: machine): Das Kompatibilitätsfenster enthält nur die aktuelle und genau eine genau benannte, attestierte Vorgängerversion; unbeschränkte oder implizite Legacy-Kompatibilität ist verboten.
- `downlevel-refusal-and-offline-staged-path` (enforcement: machine): Nicht unterstützte Downlevel-Versionen werden abgewiesen, außer ein dokumentierter Offline-Stufenpfad mit expliziten Zwischenschritten vorliegt; eine endlose Migratorenkette ist verboten.
- `deterministic-dry-run-and-cutover-rebind` (enforcement: machine): Der Dry-run bindet Eingaben, Digests, Aktionen, Rollback und erwartete Zielidentität deterministisch; am Cutover werden dieselben Eingaben mittels Compare-and-Swap und Fencing erneut gebunden.
- `idempotent-lifecycle-phases` (enforcement: machine): Install, Migrate, Activate und Rollback sind jeweils idempotent und liefern bei Wiederholung dieselbe attestierbare Zielwirkung oder HOLD.
- `staged-provenance-before-publish` (enforcement: machine): Vor der Publikation werden Herkunft, Integrität und erwartete Identität der gestagten Generation attestiert; nicht attestierte Artefakte dürfen nicht publiziert werden.
- `self-contained-release-bundle` (enforcement: machine): Das Release-Bundle ist selbstenthalten und darf weder vom Worktree noch von einer interaktiven Shell oder einem impliziten PATH abhängen.

### transaction-publication-and-recovery

Ein dauerhafter, gefenceter Transaktionsablauf verhindert Teilzustände, fremde Überschreibungen und unkontrollierte Wiederholungen bei Fehlern oder Abstürzen.

Maschinenvertrag (nur Source-/Compiler-Durchsetzung): `{"crash_recovery":"durable_resume_or_hold","install_activate":"separate","journal":{"allowlist":true,"durability":"fsync","max_bytes":8388608,"redaction_test":true,"rollback_guard":"cas_fencing","rollback_order":"inverse","snapshot_kinds":["pointer","file","service_unit","state"],"storage_failure":"block_publish"},"lock":{"fencing":true,"owner":"single","transaction_id":"monotone"},"operator_abort":{"after":"hold","auto_rollback_max":1},"owner_mode_drift":"revalidate_before_mutation_and_publish","publish_before_activate":true,"replay":{"plan_digest":true,"transaction_fence":true}}`

- `complete-snapshot-journal-and-inverse-fenced-rollback` (enforcement: machine): Das Transaktionsjournal snapshotet alle betroffenen Pointer, Dateien, deklarierte Service-Units und Zustände; Rollback läuft in umgekehrter Reihenfolge und verwendet Compare-and-Swap sowie Fencing, damit fremde Änderungen nicht überschrieben werden.
- `atomic-publication-before-consumer-activation` (enforcement: machine): Manager- oder Consumer-Aktivierung erfolgt erst nach vollständig atomarer Publikation der attestierten Generation.
- `install-separate-from-activate` (enforcement: machine): Installation und Aktivierung sind getrennte, einzeln attestierbare Schritte.
- `single-owner-monotone-transaction-fencing` (enforcement: machine): Ein Single-Owner-Lock sowie monotone Transaktions-IDs und Fencing verhindern Parallelstarts, stale writer und ABA.
- `replay-fence-and-plan-digest` (enforcement: machine): Alte oder wiederholte Transaktionen werden durch Transaktions-Fence und Plan-Digest abgewiesen.
- `durable-crash-resume-or-hold` (enforcement: machine): Reboot oder Prozesscrash mitten im Cutover werden aus einem dauerhaften Journal deterministisch als Resume oder HOLD behandelt; ein unjournalisierter Weiterlauf ist verboten.
- `operator-abort-one-rollback-then-hold` (enforcement: machine): Ein Operator-Abbruch löst höchstens einen automatischen, gefenceten Rollback aus; danach ist HOLD erforderlich.
- `storage-fsync-failure-blocks-publish` (enforcement: machine): Disk-full-, Journal- oder fsync-Fehler werden als Speicherfehler klassifiziert und blockieren die Publikation.
- `owner-and-mode-drift-revalidation` (enforcement: machine): Owner-, Berechtigungs- oder Modusdrift wird vor Mutation und Publikation erneut validiert und führt bei Abweichung zu HOLD.

### failure-observation-and-retention

Begrenzte Versuche, zeitgebundene Beobachtung und kontrollierte Bereinigung verhindern Pingpong, festhängende Rollouts und das Fortleben gefährlicher Generationen.

Maschinenvertrag (nur Source-/Compiler-Durchsetzung): `{"after_auto_rollback":"hold","attested_lease":"monotone_or_attested","identical_live_failure_limit":2,"irreversible":{"mode":"forward_only","pre_snapshot":true,"tested_roll_forward":true},"new_cause_evidence":true,"observation_timeout_seconds":3600,"regression_test":true,"remote_partition":"bounded_retry_or_hold","retention":{"gc_after":"confirmed_consumer_switch_and_observation","security_denylist":"immediate_exception"}}`

- `two-identical-live-failures-require-new-evidence` (enforcement: machine): Nach zwei identischen Live-Fehlschlägen ist ein dritter Versuch bis zu neuer Ursachenevidenz und einem Regressionstest gesperrt.
- `bounded-observation-one-auto-rollback-then-hold` (enforcement: machine): Vor Commit gilt ein begrenztes Beobachtungsfenster mit hartem Timeout; bei Fehlschlag ist maximal ein automatischer Rollback erlaubt, danach HOLD ohne Rollback-Pingpong.
- `irreversible-forward-only-roll-forward` (enforcement: machine): Irreversible Migrationen sind forward-only, besitzen einen Pre-Snapshot und einen getesteten Roll-forward statt eines vorgetäuschten Rollbacks.
- `deferred-gc-with-security-denylist-exception` (enforcement: machine): Garbage Collection erfolgt erst nach bestätigtem Consumer-Wechsel und Beobachtungsfenster; eine explizite Security-Denylist oder Notfallausnahme darf eine gefährliche alte Generation sofort entfernen.
- `bounded-remote-partition-handling` (enforcement: machine): Teilnetz- oder Remote-Hive-Unterbrechungen erhalten nur begrenzte Retries und enden deterministisch in HOLD statt in unendlichem Warten.
- `monotone-time-and-attested-lease` (enforcement: machine): Lease-Ablauf und Zeitentscheidungen verwenden monotone Zeit oder eine attestierte Lease, damit Clock-Skew nicht zu paralleler Autorität führt.
- `attested-host-version-preflight` (enforcement: machine): Divergente Hostversionen werden im Preflight attestiert; nicht unterstützte Mischstände blockieren den Cutover.

### evidence-contracts-and-telemetry

Redigierte Evidenz, echte Consumer-Verträge und begrenzte Telemetrie machen reale Auswirkungen sichtbar, ohne Secrets oder unkontrollierte Datenmengen zu erzeugen.

Maschinenvertrag (nur Source-/Compiler-Durchsetzung): `{"compiler":{"artifact_digest":true,"canonical_source":true,"staleness_test":true},"consumer_contracts":{"classes":["launcher","hook","protocol_endpoint","service_unit","stable_name"],"real_e2e_minimum":1},"crash_faultpoint":"after_each_mutating_phase","error_classes":{"deterministic":"policy_or_schema","retry_mode":"bounded","retryable":"infrastructure"},"fixture":{"digest":true,"periodic_structure_compare":true,"source":"redacted_real_live"},"snapshot":{"allowlist":true,"max_bytes":8388608,"redaction_test":true,"secret_free":true},"telemetry":{"bounded_fields":true,"fields":["duration","phase","transaction_id","failure_class","rollback","final_identity"],"fixed_schema":true,"retention_seconds":2592000,"secret_free":true}}`

- `redacted-live-fixture-digest-and-periodic-structure-compare` (enforcement: machine): Eine redaktierte Real-Live-Fixture ist ein Regressionstest; Fixture-Digest und periodischer redaktierter Vergleich mit der Live-Struktur erkennen Drift ohne Secrets.
- `snapshot-allowlist-redaction-and-size-limit` (enforcement: machine): Snapshots verwenden eine Allowlist, einen Redaktionstest und ein Größenlimit; Secrets dürfen weder im Journal noch in Fixtures oder Telemetrie erscheinen.
- `crash-faultpoint-after-each-mutating-phase` (enforcement: machine): Nach jeder mutierenden Phase prüft ein Crash-Injection-Faultpoint Recovery, Resume oder HOLD.
- `consumer-contracts-with-real-end-to-end` (enforcement: machine): Consumer-Vertragstests decken Launcher, Hooks, konfigurierte Protokollendpunkte einschließlich MCP soweit vorhanden, deklarierte Service-Units und stabile Namen ab; mindestens ein echter Consumer-End-to-End-Vertrag ist erforderlich.
- `focused-tests-before-independent-review` (enforcement: governance): Fokussierte Tests laufen vor einer finalen unabhängigen Review; externe Review ist optional und zusätzlich und darf nicht dauerhaft blockieren.
- `bounded-secret-free-migration-telemetry` (enforcement: machine): Migrations-Telemetrie enthält Dauer, Phase, Transaktions-ID, Fehlerklasse, Rollback und finale Identität, aber keine Secrets; feste Schemata, begrenzte Felder und Retention verhindern Kardinalitäts- oder Speicherexplosion.
- `failure-classification-retry-policy-schema` (enforcement: machine): Fehler werden mindestens in retrybare Infrastrukturfehler und deterministische Policy- oder Schemafehler klassifiziert; nur die erste Klasse darf begrenzt retried werden.
- `canonical-policy-source-artifact-digest-staleness` (enforcement: machine): Eine kanonische Policy-Quelle erzeugt Artefakte mit Digest; ein Staleness-Test blockiert abweichende oder veraltete Projektionen.

### diagnostic-evidence-and-remediation-gates

Getrennte, frische und begrenzte Diagnostikevidenz verhindert, dass ein wachsender Harness, generische Klassifikation oder unverifizierte Beobachtungen zur zweiten Produktautorität werden.

Maschinenvertrag (nur Source-/Compiler-Durchsetzung): `{"baselines":{"claim_without_prebaseline":"deny","post_baseline":"required","pre_baseline":"immutable_redacted_required","quiescence":"required"},"canary":{"canonical_artifact_mutation":"deny","first_failed_layer":"stop","layers":["manager_syntax_transport","namespace_sandbox","helper","product_logic"]},"classifier":{"contract":"versioned_closed","generic_after_improved_classification_limit":2,"negative_matrix":"complete_pre_live_supported_families","unknown":"fail_closed"},"cleanup":{"foreign_object_mutation":"deny","fresh_owner_check":"required","result_precedence":"cleanup"},"diagnostic_gates":{"activation":"separate_remediation_gate","diagnostic":"separate","root_cause_for_product_activation":"required"},"evidence_freshness":{"cutover":"fresh_ttl_only","stale":"block","ttl_declaration":"required"},"fixture_gate":{"activation_and_cutover":"required","policy_and_diagnostic_integration":"not_required"},"harness_scope":{"bound_declarations":["files","production_loc","error_families","live_attempts"],"exceedance":{"design_review":"required","native_alternative":"required","silent_growth":"deny"}},"live_attempts":{"blind_identical_retry":"deny","maximum":1,"per":"evidence_changing_reviewed_commit"},"migration_decision":{"full_rebuild":"requires_minimal_fix_comparison_and_justification","minimal_fix":"preferred_when_root_cause_closed"},"phases":{"gated":["install","activate","observe","commit"]},"post_blind_diagnostic_revision":{"limit":2,"next":"hold"},"pre_generation_compatibility":{"before":["generate","mutation"],"dimensions":["manager","runtime","client","features"],"matrix":"required"},"telemetry":{"activation_authority":"deny","before_root_cause":"reviewed_bounded_secret_free_observability_only","second_authority":"deny"}}`

- `separate-diagnostic-and-remediation-activation-gates` (enforcement: machine): Diagnostikgate sowie Remediation- und Produktaktivierungsgate sind getrennt; ohne belegte Root Cause darf Diagnostik keine Produktaktivierung freigeben.
- `reviewed-observability-only-telemetry-before-root-cause` (enforcement: machine): Vor bekannter Root Cause darf nur reviewte, begrenzte und secretsfreie Telemetrie für Observability integriert werden; sie ist weder zweite Autorität noch Aktivierungsfreigabe.
- `one-canary-attempt-per-evidence-changing-reviewed-commit` (enforcement: machine): Pro evidenzveränderndem, reviewtem Commit ist höchstens ein Live- oder Canary-Versuch zulässig; identische Blindretries sind verboten.
- `generic-results-stop-harness-expansion` (enforcement: machine): Zwei trotz verbesserter Klassifikation generische Ergebnisse stoppen weiteren Harness-Ausbau; danach ist native Plattformdiagnostik oder eine explizite Userentscheidung erforderlich.
- `declared-diagnostic-harness-scope-budget` (enforcement: machine): Der Diagnoseharness deklariert Bounds für Dateien, Produktions-LOC, Fehlerfamilien und Liveversuche; eine Überschreitung verlangt Designreview und eine einfachere native Alternative statt stillen Wachstums.
- `versioned-closed-classifier-negative-matrix-and-fail-closed-unknown` (enforcement: machine): Der Fehlerklassifikator ist ein versionierter geschlossener Vertrag; vor Live beweist eine Negativmatrix jede unterstützte Fehlerfamilie, und unbekannte Ergebnisse bleiben fail-closed.
- `layered-canary-first-failure-stops` (enforcement: machine): Canarys prüfen in der Reihenfolge Manager-Syntax/Transport, Namespace/Sandbox, Helper, Produktlogik; die früheste rote Schicht beendet den Lauf und darf kanonische Artefakte nicht mutieren.
- `immutable-prebaseline-postbaseline-and-quiescence` (enforcement: machine): Vor jeder Mutation wird eine immutable, redigierte Pre-Baseline erhoben; Post-Baseline und Quieszenz gehören zum Ergebnis, und ohne Pre-Baseline ist keine Unverändertheitsbehauptung zulässig.
- `cleanup-precedence-and-foreign-object-protection` (enforcement: machine): Das Cleanup-Ergebnis hat Vorrang vor Primärdiagnose; Owner wird vor jeder Cleanup-Mutation frisch geprüft, und fremde Objekte werden niemals verändert.
- `fixture-required-for-activation-not-policy-integration` (enforcement: machine): Eine redaktierte Real-Live-Fixture ist vor Aktivierung oder Cutover Pflicht, aber kein Gate für die Integration einer Policy oder Diagnostik, die diese Fixture erst ermöglicht.
- `fresh-evidence-ttl-cutover-gate` (enforcement: machine): Liveevidenz besitzt eine deklarierte TTL; veraltete Evidenz blockiert Cutover und kann kein Gate öffnen.
- `gated-install-activate-observe-commit-phases` (enforcement: machine): Installieren, Aktivieren, Beobachten und endgültiges Committen bleiben getrennte Phasen mit jeweils eigenem Gate.
- `minimal-fix-comparison-before-runtime-rebuild` (enforcement: machine): Ein vollständiger Runtimeumbau ist nur mit Vergleich gegen einen lokalen getesteten Minimalfix und dokumentierter Migrationsbegründung zulässig; der Minimalfix ist vorzuziehen, wenn er die Root Cause schließt.
- `two-blind-diagnostic-revisions-then-hold` (enforcement: machine): Nach zwei blind gebliebenen Diagnoserevisionen ist HOLD verbindlich; eine dritte Klassifikationsarchitektur ist verboten.
- `compatibility-matrix-before-generate-or-mutate` (enforcement: machine): Vor Generierung oder Mutation prüft eine Kompatibilitätsmatrix Manager-, Runtime- und Clientversionen sowie unterstützte Eigenschaften; nicht belegte Kombinationen blockieren.

<!-- hive-runtime-migration-policy-v1:end -->
