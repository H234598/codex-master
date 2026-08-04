# Task 1 — Recovery Fixrunde 1

## RED

- Neue Parser-Regression: `normalize_recovery_document` mit
  `blocking_error_codes=[[]]` endete vor Fix in `TypeError: unhashable type:
  'list'` statt `FleetRecoveryValidationError("invalid_fleet_recovery")`.
- Neue Serialisierungs-Regressionen: direkt konstruierte Journale mit
  `schema_version=2` beziehungsweise fremdem `result_code` wurden vor Fix ohne
  Fehler durch `recovery_document` ausgegeben.
- Mutationen, die Tests fangen: Entfernen des `str`-Guards vor
  `RESULT_CODES`-Mitgliedschaft; Entfernen der Normalisierung vor Rückgabe aus
  `recovery_document`.

## GREEN

- Parser prüft jeden `blocking_error_codes`-Wert zuerst auf `str`; fremde Werte
  werden einheitlich als `invalid_fleet_recovery` abgewiesen.
- `recovery_document` erzeugt nur noch Dokumente, die den vollständigen
  Normalisierungsvertrag bestehen. Ungültige öffentliche Dataclass-Objekte
  werden vor Rückgabe abgewiesen; keine Rohwerte werden zurückgegeben.
- Oversize-Test erzeugt absichtlich ungültiges Eingabedokument nun durch
  Mutation eines gültigen serialisierten Dokuments.

## Verifikation

- RED: 3 erwartete Fehler (1 `TypeError`, 2 fehlende Validierungsfehler).
- Neue Regressionen GREEN: 3 bestanden.
- `PYTHONPATH=src python -m pytest tests/test_fleet_recovery.py -q`: bestanden.
- `python -m compileall -q src/codex_master/fleet_recovery.py tests/test_fleet_recovery.py`: bestanden.
- `ruff check src/codex_master/fleet_recovery.py tests/test_fleet_recovery.py`: bestanden.
- `git diff --check`: bestanden.
- `PYTHONPATH=src python -m pytest -q`: bestanden.

## Dateien

- `src/codex_master/fleet_recovery.py`
- `tests/test_fleet_recovery.py`
- `.superpowers/sdd/Flottenregister-Task-5b-Recovery-Journal-Implementierungsplan/task-1-report.md`

## Risiken

- Keine bekannten. Direkte Dataclass-Konstruktion bleibt technisch möglich,
  aber ungültige Werte verlassen `recovery_document` nicht mehr.
