# Task 1: Ressourcen-Policy und data-sparse Admission-Entscheidung

## Implementierung

- `spawn_resource_policy()` liefert die festen Grenzwerte: Load/CPU `0.85`, verfügbarer RAM mindestens `20.0%` und `1024 MiB`, höchstens sechs verwaltete Agentinnen.
- `system_resource_snapshot()` liest nur klassifizierte Werte: CPU-Anzahl und 1-Minuten-Load, `MemTotal`/`MemAvailable` aus `/proc/meminfo` sowie nur konfigurierte tmux-Sessions. Fehlende oder ungültige Evidenz erzeugt einen der erlaubten Unavailable-Reason-Codes; keine Rohwerte, Pfade, Environment-Werte oder Sessionnamen werden zurückgegeben.
- `spawn_admission_decision()` validiert `required_slots`, Policy und Snapshot fail-closed und meldet Druck, Limits oder fehlende Slots mit erlaubten Reason-Codes.
- `AgentCapacityError` enthält einen öffentlichen Payload; `public_error_payload()` übernimmt ihn wie bestehende Busy-/Readiness-Payloads.

## Tests und Ergebnisse

- GREEN: `PYTHONPATH=src python -m unittest tests.test_server.ServerHelpersTest -k spawn_admission -v` — 7 Tests, OK.
- GREEN: vier Telemetrie-/Payload-Tests — 4 Tests, OK.
- GREEN: `PYTHONPATH=src python -m unittest tests.test_server -v` — vollständiges `tests.test_server` beendet ohne gemeldeten Testfehler.
- Zusätzlich: `git diff --check` und `python -m py_compile src/codex_master/server.py tests/test_server.py` — OK.

## Ehrliche TDD-Evidenz

Die übernommene Änderung enthielt die Implementierung bereits; ihre fokussierten Tests waren mit Worktree-Import grün. Daher RED gegen die Basisrevision hergestellt: ein isolierter Import von `HEAD:src/codex_master/server.py` endete mit `ImportError: cannot import name 'spawn_admission_decision' from 'codex_master.server'`. Damit fehlten vor Task 1 die geforderten Interfaces. Der erste unpräfixierte Testlauf importierte den editable Hauptcheckout statt diesen Worktree und schlug deshalb ebenfalls beim fehlenden `AgentCapacityError` fehl; alle maßgeblichen Läufe verwenden folglich `PYTHONPATH=src`.

## Dateien geändert

- `src/codex_master/server.py`
- `tests/test_server.py`
- `.superpowers/sdd/Ressourcenaware MCP bzw. spawns/task-1-report.md`

## Selbstreview

- Grenzwerte: Gleichstand erlaubt, Policy-Verletzungen gesperrt.
- Ungültige Zahlen, Bool-as-int, unvollständige Speicherwerte, fehlende CPU-Anzahl und fremde tmux-Sessions abgedeckt.
- `insufficient_slots`, Privacy und Capacity-Error-Payload zusätzlich abgedeckt.
- Keine MCP-Tools, CLI, Start-Gate, Assignment-Logik oder Dokumentation späterer Tasks verändert.

## Concerns

- Lokale editable Installation verweist auf `/home/teladi/codex-master`; ohne `PYTHONPATH=src` testen Python-Unittests nicht den übernommenen Worktree.
