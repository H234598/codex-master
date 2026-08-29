<!-- codex-master-common-policy:{"generation":7,"schema_version":1} -->
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

Der zitierte Annotation-Quellabschnitt erhält genau eine idempotente
Bidirektionszeile in exakt diesem Format:
`Beantwortung der Frage am TT.MMJJJJ durch: <Biene> -: [[<Antwortziel>#<Antwortüberschrift>|<Antwortüberschrift>]]`.
`<Biene>` muss durch die konkrete Biene, `<Antwortziel>` durch das konkrete
Antwortziel und `<Antwortüberschrift>` durch die konkrete Antwortüberschrift
ersetzt werden.

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
