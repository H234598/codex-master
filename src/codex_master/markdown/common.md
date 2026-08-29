<!-- codex-master-common-policy:{"generation":2,"schema_version":1} -->
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

## Bidirektionale Annotation-Antworten in Obsidian

Eine beantwortete Annotation erhält ein eigenes Kapitel am Dokumentende. Seine
Überschrift übernimmt die exakte Annotation-Überschrift und
endet mit einem Markdown-Selbstlink auf die Annotation-ID, zum Beispiel:
`## <Annotation-Überschrift> [[#<Annotation-ID>|<Annotation-ID>]]`. Die
sichtbare ID bleibt unverändert. Antworten, Erklärungen, ADRs und Fragen
bleiben jeweils eigene Kapitel am Dokumentende und werden nicht zu einem
Sammelkapitel oder Inline-Text zusammengezogen.

Der zitierte Annotation-Quellabschnitt erhält genau eine idempotente
Bidirektionszeile in exakt diesem Format:
`Beantwortung der Frage am TT.MMJJJJ durch: <Biene> -: [[<Antwortziel>#<Antwortüberschrift>|<Antwortüberschrift>]]`.
`<Biene>` muss durch die konkrete Biene, `<Antwortziel>` durch das konkrete
Antwortziel und `<Antwortüberschrift>` durch die konkrete Antwortüberschrift
ersetzt werden. Vor jedem Retry ist die bestehende Zeile anhand von Annotation,
Ziel und Überschrift zu prüfen; existiert sie bereits, wird keine zweite Zeile
angelegt.

Vor jeder Änderung einer Obsidian-Quelldatei ist das passende Annotation
Marker-Sidecar unter `.obsidian/plugins/annotation-marker/annotations/` zu
finden und auszuwerten. Fehlt das passende Sidecar, wird die Quelldatei nicht
geändert. Die Regeln für `color1` bis `color6`, `data-annotation-note` als
User-Notiz und `data-annotation-id` als eindeutige Marker-ID bleiben bindend;
Marker und ihre Notizen werden erhalten.
