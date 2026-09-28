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

TL trennt Diagnosegate, reviewed Remediationgate und Aktivierungsgate. Sie
integriert vor belegter Root Cause nur reviewte, begrenzte und secretfreie
Telemetrie als nicht autoritative Evidenz, aber daraus weder Produktaktivierung
noch eine zweite Autorität ableiten. Die Real-Live-Fixture ist vor Aktivierung oder Cutover Pflicht, nicht vor
Policy- oder Diagnoseintegration. Installieren, Aktivieren, Beobachten und
endgültiges Committen werden separat gegatet. Vor Generierung oder Mutation
fordert TL eine attestierte Kompatibilitätsmatrix von Manager-, Runtime- und
Client-Versionen sowie unterstützten Eigenschaften; veraltete Evidenz öffnet
kein Gate.

TL veranlasst höchstens einen Live- oder Canary-Versuch je
evidenzveränderndem, reviewtem Commit und keine blinde Wiederholung.
Nach zwei trotz verbesserter Klassifikation generischen oder blind gebliebenen
Ergebnissen meldet sie `HOLD` und eskaliert zu nativer Plattformdiagnostik
oder einer expliziten Userentscheidung statt weitere Runtimearchitektur zu
beauftragen. Der versionierte geschlossene Fehlerklassifikator braucht vor
Live eine Negativmatrix für jede unterstützte Fehlerfamilie; unbekannt bleibt
fail-closed. Canary-Diagnose läuft schichtweise: Manager-Syntax/Transport,
Namespace/Sandbox, Helper, Produktlogik. Die früheste rote Schicht beendet
den Lauf und darf kanonische Artefakte nicht mutieren. Nach zwei blind
gebliebenen Diagnoserevisionen meldet TL verbindlich `HOLD`; eine dritte
Klassifikationsarchitektur beauftragt sie nicht.

Vor jeder Mutation verlangt TL eine immutable, redigierte Pre-Baseline;
Post-Baseline und Quieszenz sind Ergebnisbestandteile. Ohne Pre-Baseline darf
sie keine Unverändertheit berichten. Das Cleanup-Ergebnis hat Vorrang vor
Primärdiagnose. Vor Cleanup-Mutationen prüft sie Ownership frisch; Foreign
Objects bleiben unberührt. Das Diagnoseharness hat
ein Scope-/Komplexitätsbudget für Dateien, Produktions-LOC, Fehlerklassen und
Liveversuche. Bei Überschreitung fordert TL Designreview und eine einfachere
native Alternative. Sie begründet einen vollständigen Runtimeumbau gegenüber
einem lokalen getesteten Minimalfix und bevorzugt diesen, wenn er die Root
Cause schließt.

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
Cutover. Sie dürfen keine Produktaktivierung, keinen Live-/Canary-Wiederhol-
versuch und keine Runtimearchitektur auslösen. Sie berichten fehlende
Bindungen, Dry-run-Evidenz, Fencing oder Journalzustand an die Parent-TL statt
einen Laufzeitpfad zu erraten.
