# TL- und Workerführung

TL startet Workerinnen. Vor Auswahl attestiert sie aktuelle Generation,
Rolle, Lifecycle, Principal, Lease, Scope, Capability, Auth-/Quota-, Kosten-
und Ressourcengates. Sie erfindet weder Modell noch Reasoning noch Provider.

## Arbeitsform

TL hält jede Workerin möglichst bei einem Thema und einer Datei und bleibt
selbst themenlokal. Schreibende Workerinnen ergänzen für jede neue oder
berührte ungetestete Funktion einen aussagekräftigen Test. Gezielt testen;
Full Suite selten.

## Runtime-Migrationspakete

Eine kleine Feature-Änderung und eine Runtime- oder Installationsmigration
sind getrennte Pakete. TL prüft vor Delegation das Scope-/Budget-Gate: Ergibt
sich unerwartet Migration, wird sie als eigenes Voraussetzungspaket mit
eigenem Scope, Budget und Handoff angelegt; das Feature wächst nicht still.
Vor Entwicklung und vor einem angefragten Cutover sammelt TL einen
Read-only-Live-Preflight nach der
[Runtime-Migrationspolicy v1](../../../src/the_hive/markdown/runtime-migration-policy-v1.json).
Dieser Skill und der MCP-Koordinationspfad bleiben evidenzbasiert und
read-only; sie dürfen weder Install noch Activate noch Reload noch Cutover
ausführen oder erlauben.

Vor der finalen unabhängigen Review führt TL die fokussierten Tests aus und
fordert mindestens einen echten Consumer-E2E-Vertrag als Evidenz. Die
Policypflicht umfasst gebundenen Dry-run, CAS/Fencing, Journal,
Rollback/HOLD sowie redigierte, begrenzte secret-freie Telemetrie.
Kompatibilität ist nur der genau benannte, attestierte
Vorgängerversion-Input der Policy, niemals ein impliziter Fallback.

TLs und lesende Workerinnen sammeln bounded und berichten einmal. Echte
Security-, Scope- oder Datenverlustblocker werden sofort gemeldet. Für ein
passendes erneutes Thema bevorzugt TL Topicresume einer vorhandenen Session
gegenüber einer neuen Biene.

## Peergrant und Führungspfad

Der Worker-Peergrant wird bei Assignment oder Resume für dieselbe Parent-TL
und belegte Task-DAG-Abhängigkeit materialisiert. Es gibt kein Handshake je
Datagramm. Gebundene Peers dürfen innerhalb Budget informieren oder fragen;
eine Workerin darf keine Biene starten, kann aber `spawn.requested` nur an
ihre Parent-TL senden.

Peers erweitern weder Scope noch Assignment, Review, Acceptance oder Merge.
Führungsrelevante Entscheidungen, Blocker, Handoffs, Risiken und
Interfacewirkungen gehen genau einmal an die Parent-TL.

Workerinnen aktivieren keine ungebundene Migration oder keinen ungebundenen
Cutover. Sie berichten fehlende Bindungen, Dry-run-Evidenz, Fencing oder
Journalzustand an die Parent-TL statt einen Laufzeitpfad zu erraten.
