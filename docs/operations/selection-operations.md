# The Hive Selection Operations

## Status

Selection ist im aktuellen Quellstand ein Vorschau- und
Reihenfolgemechanismus. `selection-status` meldet `preview_only`; alle vier
SP-Flags der eingecheckten `codex-hive.json` stehen auf `false`. Es gibt daher
aus diesem Konfigurationsstand keine dokumentierte produktive Rollout-Reihen-
folge und keine Aussage über verfügbare Konten, Modelle oder Quoten.

Die Serveroberfläche kennt `selection-preview` mit `off`, `shadow` und
`enforced` als Eingabemodi. Eine Vorschau reserviert, startet, stoppt,
unterbricht oder preemptiert keine Agentin. Für eine spätere Ausführung wären
eine frische Admission sowie alle Authority-, Repository-, Scope-, Account-,
Modell-, Lease- und Konfigurationsgates erneut zu prüfen.

## Resolver und Grenzen

`agent_selection_options` liefert ein generationiertes Angebot legaler
Klasse-/Lifecycle-/Modell-/Reasoning-Tupel für eine konkrete Agentin. Es ist
eine beratende Oberfläche, keine Reservierung. Aufrufer dürfen keine
Führungsautorität als Anfragedatum heraufstufen; unbekannte Autorität fällt auf
eine nicht führende Grenze zurück.

Unbekannte oder veraltete Usage-Semantik wird nicht als freies Kontingent
interpretiert. Der Reset-Anker unterstützt eine trockene Planung, seine
Ausführung ist gegenwärtig über
`selection_proactive_anchor_safety_gate` blockiert und meldet
`mutation_performed: false`.

Der direkt eingecheckte MCP-Launcher benötigt ein attestiertes Release-Binding.
Diese Seite dokumentiert daher keine Shell-Aufrufe und keine Änderung der
Featureflags. Eine Aktivierung oder ein tatsächlicher Auswahlbetrieb ist
außerhalb ihres belegten Umfangs.
