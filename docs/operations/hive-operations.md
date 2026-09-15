# The Hive Operations

## Verifizierter Umfang

The Hive enthält einen lokalen, datenarmen Kontrollbereich für typisierte
Principals, Repository-Bindungen, Grants, Workpackages, Queue- und
Admission-Zustand sowie Reporting-Metadaten. Der Hive-CLI-Adapter implementiert
die Diagnosepfade `hive validate`, `hive status`, `hive doctor`,
`hive migration-status`, `hive runtime-status`, den ausdrücklich trockenen
`hive rollback --dry-run`, `selection-status` und die
Reset-Anker-Vorschau.

Diese Namen beschreiben Parseroberflächen im Quellstand. Der eingecheckte
`bin/the-hive-mcp`-Einstiegspunkt verlangt Release-Root, Generation und
Manifest-Digest und ist nicht als direkter Aufruf dokumentiert. Die
`.mcp.json` verweist auf den stabilen, installierten Launcher
`/home/teladi/.local/lib/the-hive-runtime/the-hive-mcp`; dessen Existenz und
aktueller Laufzeitzustand wurden nicht geprüft.

## Aktuelle Fail-closed-Grenzen

`codex-hive.json` hat zwar den Modus `enforced`, schaltet aber alle vier
SP-Featureflags aus. Die Pilot-Gate-Implementierung akzeptiert keine
bereitgestellte positive Account-Attestierung und liefert ohne die geforderte
Laufzeitevidenz einen blockierenden Grundcode. Externe Freigaben, reale
Provider-Credentials und eine produktive Pilotzulassung sind daher in diesem
Dokument nicht nachgewiesen.

Die logische Königin ist gegenwärtig nicht materialisiert. Der
Emergency-Queen-Pfad hat keine Kandidaten und meldet
`queen_spawn_unavailable:hive_queen_runtime_not_materialized`, statt einen
Erfolg zu simulieren. Ein Zustandsname oder eine vorhandene q-Home ersetzt
diese fehlende Laufzeitanbindung nicht.

Private Hive-Zustände werden in der Implementierung begrenzt, gelockt und
über no-follow-Dateiprüfungen behandelt. Historische Kennungen in
Zustandsverzeichnissen oder Umgebungsvariablen bleiben technische
Kompatibilitätsverträge, keine Produktbezeichnung.

## Operative Entscheidung

Diese Seite enthält absichtlich keine produktiven Start-, Provisionierungs-
oder Callback-Schritte. Eine solche Handlung benötigt zusätzlich einen
autorisierten Ablauf, belegte Repository- und Scope-Bindungen, frische
Laufzeitevidenz sowie die jeweils erforderlichen externen Freigaben. Für den
Berichtspfad gilt die separat begrenzte Beschreibung in
[`goddess-reporting.md`](goddess-reporting.md).
