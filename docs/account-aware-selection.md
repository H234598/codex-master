# The Hive: accountbewusste Auswahl

Die Auswahl verarbeitet Konten als lokal abgeleitete, opaque Identitäten.
Öffentliche Auswahl- und Statusdaten sollen keine Account-Schlüssel,
Provider-Credentials, Prompts oder Roh-Ausgaben enthalten.

## Aktueller Produktstand

Die eingecheckte `codex-hive.json` setzt `sp0_passive`, `sp1_deadline`,
`sp2_secondary_model` und `sp3_fairness` sämtlich auf `false`. Der
read-only-Statuspfad meldet deshalb `preview_only`. Daraus folgt keine
produktive Reservierung, Start-, Stop-, Interrupt- oder Preemption-Aktion.
Eine beobachtete Account- oder Modellerreichbarkeit wurde nicht erhoben und
bleibt unbekannt.

Die Auswahlbibliothek bietet eine deterministische Vorschau über Eignung und
Rangfolge. Fehlende, veraltete oder mehrdeutige Nutzungsdaten sind kein Grund,
ein Reset- oder Quotenereignis zu erraten. Der passive Reset-Anker kann eine
Vorschau erstellen; sein Ausführungspfad antwortet fail-closed mit
`selection_proactive_anchor_safety_gate` und führt keine Mutation aus.

## Policy-Grenze

Die private Policy wird ausschließlich über
`the_hive.selection.config.load_selection_policy` geladen. Der Loader verlangt
eine absolute, reguläre Datei ohne Symlink, begrenzt Größe und Felder und
akzeptiert für den Modus nur `disabled`, `shadow` oder `enforced`. Öffentliche
Policy-Projektionen enthalten Zähler, Feature-Zustände und einen Digest, aber
keine Allowlist-Werte.

Eine Policy-Allowlist ist keine Autorisierung, Credential-, Provider- oder
Reservierungsevidenz. Kill-Switch, fehlende oder unfrische Evidenz und nicht
erfüllte Laufzeitgrenzen bleiben blockierend. Diese Seite dokumentiert keinen
Rollout, weil die zugehörigen Produktflags derzeit deaktiviert sind.
