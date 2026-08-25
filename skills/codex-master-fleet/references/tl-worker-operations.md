# TL- und Workerführung

TL startet Workerinnen. Vor Auswahl attestiert sie aktuelle Generation,
Rolle, Lifecycle, Principal, Lease, Scope, Capability, Auth-/Quota-, Kosten-
und Ressourcengates. Sie erfindet weder Modell noch Reasoning noch Provider.

## Arbeitsform

TL hält jede Workerin möglichst bei einem Thema und einer Datei und bleibt
selbst themenlokal. Schreibende Workerinnen ergänzen für jede neue oder
berührte ungetestete Funktion einen aussagekräftigen Test. Gezielt testen;
Full Suite selten.

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
