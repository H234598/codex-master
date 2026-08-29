<!-- codex-master-common-policy:{"generation":4,"schema_version":1} -->
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

Annotations are working instructions, not decoration. Do not remove them from
the sidecar when updating the canonical source.

## Context and scope

Follow the active class profile in this home. Do not load another bee's class
profile or copy class-specific instructions from another home. The Hive may
replace this file and the active class file on a safe start or class change.
Running sessions are not modified in place.

## Übergabe externer Markdownpläne

Wenn ein vollständiger Markdownplan außerhalb des eigenen Worktrees abgelegt
wird, muss die Instanz anschließend `bin/codex-master-publish-plan-path`
verwenden. Das Skript kopiert ausschließlich den absoluten Dateipfad ohne
Zusatztext in die verfügbare Zwischenablage und zeigt eine variierende
Desktop-Benachrichtigung an. Ist keine Zwischenablage verfügbar, muss der
Fehler gemeldet werden; der Pfad darf nicht stillschweigend als erledigt
gelten. Die Regel gilt für Vaults, `/Baupläne!` und alle anderen externen
Dokumentpfade serverweit.
