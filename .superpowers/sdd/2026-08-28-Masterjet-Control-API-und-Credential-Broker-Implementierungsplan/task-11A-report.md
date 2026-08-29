# Task 11A Report: Dauerhafter Adminservice und systemd-Unit

## Ergebnis

`DONE_WITH_CONCERNS`: Der gemeinsame, bounded Lifecycle für Unix-Socket und
private HTTP-Origin, der feste Cloudflare-JWKS-Vertrag, systemd-Readiness und
die gehärtete Unit sind implementiert und getestet. Beide Adapter erhalten
identisch dieselbe `MasterjetControlService`-Instanz. Es wurde keine zweite
Servicefactory und kein HTTP-Health-Endpunkt eingeführt.

Der installierte CLI-Einstieg scheitert derzeit bewusst und stabil mit
`EX_CONFIG`/`control.owner_composition_unavailable`. Eine vollständige
produktive Servicekomposition ist mit den bestehenden Konstruktoren nicht
wahrheitsgetreu möglich: Es fehlen konkrete produktive Implementierungen bzw.
eine bestehende Assembly für `AccountRegistryPort`, `OpenAIAccountsPort`,
`QuotaCollectorPort` und `GoogleProvisionerPort` sowie die benötigten
Credential-Authorities/Writer für Google OAuth und Billing. Test-Doubles oder
eine nur scheinbar vollständige, degradierte Komposition wurden deshalb nicht
als Produktion verdrahtet.

## TDD- und RED-Evidenz

Jeder neue Test benennt im Docstring den realen Produktionsbruch, den er
absichert.

1. Vor Produktcode:

   ```text
   PYTHONPATH=src pytest tests/test_admin_daemon.py tests/test_admin_systemd.py -v
   ERROR collecting tests/test_admin_daemon.py
   ModuleNotFoundError: No module named 'codex_master.admin_daemon'
   ```

   Damit waren Daemon-/Readiness-/Shutdown-/JWKS-Vertrag und CLI produktiv
   nicht vorhanden; Unit-/Entrypoint-Anforderungen waren ebenfalls noch rot.

2. Erster Lauf nach der minimalen Implementierung:

   ```text
   21 passed, 1 failed
   test_failed_jwks_refresh_never_destroys_last_known_good:
   assert verifier.refresh() is False  # war fälschlich True
   ```

   Reale Regression: Ein leerer neuer Key-Satz wurde erst mit dem vorherigen
   Satz zusammengeführt und dadurch fälschlich als erfolgreicher Refresh
   akzeptiert. Minimaler Fix: Jeden neuen Satz eigenständig durch
   `CloudflareAccessVerifier` validieren, erst danach aktuellen und vorherigen
   Satz atomar publizieren.

3. Gezielter Regressionstest und kompletter Fokuslauf danach:

   ```text
   1 passed
   22 passed
   ```

## Änderungen

- `src/codex_master/admin_daemon.py`
  - gemeinsamer Owner-Lifecycle mit Readiness erst nach beiden Binds;
  - Teilstart-Rollback nur für bereits übernommene Ressourcen;
  - SIGTERM/SIGINT setzen nur das Stop-Ereignis; Cleanup läuft kontrolliert;
  - paralleles Stoppen der HTTP-Admission und des Socket-Lifecycles;
  - bounded HTTP-Drain, Socket-/HTTP-/Authority-/JWKS-Cleanup;
  - jeder unvollständige Cleanup führt zu einem Fehlerstatus;
  - `READY=1`/`STOPPING=1` über privates systemd-Notify-Socket;
  - Cloudflare-JWKS ausschließlich unter
    `https://<exakte-team-domain>/cdn-cgi/access/certs`;
  - Redirects verboten, 5-Sekunden-Fetch-Timeout, 64-KiB-Limit, Status-,
    Content-Type-, Content-Length- und Strict-JSON-Prüfung;
  - periodischer sowie unbekanntes-`kid`-Refresh mit bounded Worker;
  - atomarer aktueller/vorheriger Last-Known-Good-Satz;
  - Observability enthält nur `refreshed_at` und Key-IDs;
  - CLI scheitert an der konkret dokumentierten Owner-Lücke fail closed.
- `systemd/codex-master-admin.service`
  - dedizierter User/Gruppe, private Runtime-/StateDirectory-Modi und `UMask`;
  - Write-Zugriff nur auf Runtime- und StateDirectory;
  - alle vorgesehenen Credentials ausschließlich über `LoadCredential=`;
  - kein `Environment=`, `EnvironmentFile=` oder Secret im `ExecStart`;
  - `Type=notify`, `Restart=on-failure` und enger Sandbox-/Capability-Rahmen;
  - keine Desktop-/GUI-Session und kein Health-Probe.
- `pyproject.toml`
  - Entrypoint `codex-master-admin = codex_master.admin_daemon:main`.
- `tests/test_admin_daemon.py`, `tests/test_admin_systemd.py`
  - 22 fokussierte Tests für die oben genannten Produktionsbrüche.

## Verifikation

- Fokus: `22 passed`.
- Relevante Admin-Integration (`admin_auth`, `admin_http`, `admin_socket` plus
  Tasktests): `186 passed`, ein `BrokenPipeError` im unveränderten
  Oversize-HTTP-Clienttest; isolierte Wiederholung: `1 passed`.
- Task-Ruff: grün.
- Task-Formatcheck: grün.
- Task-Mypy mit `--follow-imports=skip`: grün; normaler Importlauf enthält
  keine Task-11A-Diagnose, wird aber von der bestehenden Repository-Mypy-
  Baseline überlagert.
- Compileall für `src/codex_master` und `tests`: grün.
- `git diff --check`: grün.
- Secretmarker-Scan der Taskdateien: grün.
- `systemd-analyze verify`: Unit wird geparst; erwarteter Worktree-Hinweis,
  dass `/usr/bin/codex-master-admin` vor Installation noch nicht existiert.
- Vollsuite: `6076 passed, 2 skipped, 3 failed, 636 subtests passed`.
  Zwei langlaufbedingte Admission-Expiry-Fehler bestanden bei isolierter
  Wiederholung. Ein unveränderter Server-Test bleibt isoliert wegen bestehendem
  `fleet_recovery_pending` rot.
- Repositoryweite unveränderte Baselines: drei Ruff-Befunde, 182 Dateien
  außerhalb Task 11A nicht im aktuellen Ruff-Format sowie zahlreiche
  importierte Mypy-Befunde. Keine fremde Datei wurde dafür geändert.

## Risiken und offene Lücken

1. Höchstes Risiko: Bis eine echte Business-Owner-Assembly bereitsteht, ist
   `codex-master-admin` absichtlich nicht produktiv startbar. systemd startet
   keinen scheinbar gesunden Teildienst, sondern behandelt dies durch
   `EX_CONFIG` und `Restart=on-failure` als Fehler.
2. Die Unit kann im Worktree nicht vollständig gegen den installierten Pfad
   geprüft werden; Packaging/Installation muss `/usr/bin/codex-master-admin`
   bereitstellen und den dedizierten Systemuser anlegen.
3. Die oben genannten Repository-Baselines liegen außerhalb Task 11A und
   bleiben unverändert.

## Commit

Commit-Nachricht: `feat: run masterjet admin transports concurrently`.
Dieser Report ist Bestandteil desselben Task-Commits; der resultierende Hash
steht in der Abschlussübergabe.
