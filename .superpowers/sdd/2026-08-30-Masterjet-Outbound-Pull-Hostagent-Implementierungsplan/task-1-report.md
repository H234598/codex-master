# Task 1 Report: Exakte Agentverträge

## Ergebnis

`DONE`: Die privaten, fail-closed Agentverträge für Poll, Lease, Receipt und
Result sind in `src/codex_master/agent_contracts.py` umgesetzt. Die Parser
akzeptieren exakte Feldmengen, lehnen freie Host-/Command-/Path-/Credential-
Schlüssel ab, binden `arguments_digest` und `result_digest` kanonisch und
erzwingen die feste Allowlist `host.probe collect` sowie
`ollama.instance plan|apply|probe|stop`.

## Geänderte Dateien

- `src/codex_master/agent_contracts.py`
- `tests/test_agent_contracts.py`
- `.superpowers/sdd/2026-08-30-Masterjet-Outbound-Pull-Hostagent-Implementierungsplan/task-1-report.md`

## RED

Command:

```text
PYTHONPATH=src pytest -q tests/test_agent_contracts.py
```

Relevanter erwarteter Fehler:

```text
ERROR collecting tests/test_agent_contracts.py
ModuleNotFoundError: No module named 'codex_master.agent_contracts'
```

## GREEN

Command:

```text
PYTHONPATH=src pytest -q tests/test_agent_contracts.py
```

Ergebnis:

```text
27 passed in 0.59s
```

## Verifikation

- `ruff check src/codex_master/agent_contracts.py tests/test_agent_contracts.py`
  → `All checks passed!`
- `python -m compileall src/codex_master/agent_contracts.py tests/test_agent_contracts.py`
  → erfolgreich
- `git diff --check`
  → erfolgreich

## Self-Review

- DTOs sind `frozen=True` und `slots=True`; die Validierung liegt zentral in
  kleinen, wiederverwendeten Helfern.
- `parse_agent_poll()` und `parse_agent_receipt()` prüfen strikt auf exakte
  Top-Level-Felder und exakte `schema_version == 1`.
- `serialize_agent_lease()` und `serialize_agent_result()` geben nur die
  expliziten Wire-Felder aus; keine freien Fehlertexte, Pfade oder Credentials
  werden erzeugt.
- `arguments_digest` und `result_digest` werden gegen kanonisches JSON mit
  `sort_keys=True` und kompakten Separatoren gebunden.
- Die Tests prüfen reales Parser-/Serializerverhalten, inklusive Bool-als-Int,
  Range-Limits, Digestdrift, doppelte bzw. zu viele `reason_codes`,
  verbotene Schlüssel und das 256-KiB-Limit.

## Risiken

1. `arguments` und `result.payload` sind absichtlich nur generisch-bounded
   JSON-Mappings; operation-spezifische Feldschemata werden erst in den
   nachfolgenden Queue-/Executor-Tasks konkretisiert.
2. Der im Prompt genannte Report-Templatepfad war im Worktree nicht vorhanden;
   dieser Report wurde deshalb direkt unter dem verlangten Zielnamen angelegt.
