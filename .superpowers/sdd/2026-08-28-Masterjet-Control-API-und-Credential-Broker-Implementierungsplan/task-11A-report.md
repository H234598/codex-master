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

---

## Fixrunde 1/5 — produktive Assembly und ehrlicher Lifecycle

Dieser Abschnitt ist die maßgebliche Fortsetzung des ursprünglichen Reports
und ersetzt dessen Aussage zum dauerhaft unstartbaren `EX_CONFIG`-Pfad. Die
Review-Befunde C1 und I1–I5 sind umgesetzt. Der installierte Entrypoint baut
jetzt einen realen Owner-Graphen und startet dauerhaft; `EX_CONFIG` ist nur
noch die fail-closed Antwort auf tatsächlich ungültige oder fehlende
Konfiguration/Credentials.

### Befund → Test → RED → Fix → Resultat

#### C1 — fehlende produktive Owner-/Credential-/Adapter-Assembly

- **Produktionsbruch:** `main()` endete unabhängig von der Installation immer
  mit `EX_CONFIG`; kein Credential wurde gelesen, kein Service erzeugt und
  kein Endpoint gebunden.
- **Test:**
  `test_installed_product_path_uses_credentials_both_adapters_and_sigterm`
  startet das durch eine lokale, indexfreie Wheel-Installation erzeugte
  Console-Script in einem isolierten venv. `PYTHONPATH` ist dabei entfernt und
  das Arbeitsverzeichnis liegt außerhalb des Repositorys. Der Test stellt
  private systemd-artige Credential-, Runtime- und State-Verzeichnisse bereit,
  wartet auf `READY=1`, schreibt über den realen Unix-Adapter und liest
  denselben Zustand authentisiert über den realen HTTP-Adapter.
- **Beobachtetes RED:** Der Prozess lieferte keine Readiness und lief in den
  Subprozess-Timeout, weil der Entrypoint immer `EX_CONFIG` zurückgab.
- **Minimaler Fix:** `admin_assembly.py` liest eine strikt begrenzte,
  duplicate-key-freie `admin-config` und alle sechs Credentials ausschließlich
  über private, no-follow, nicht vererbbare FDs aus
  `CREDENTIALS_DIRECTORY`. Es konstruiert reale persistente Registry-,
  Operation-, Host-, Secret-Ingress-, OpenAI-, Google-Inventory-, OAuth-,
  Quota-, Provisioning- und Billing-Owner/Authorities. Fehlende produktive
  Ports wurden als kleinste Adapter auf den bestehenden kanonischen
  Hive-/Vault-/Inventory-/Google-API-Quellen implementiert. Genau ein direkt
  konstruierter `MasterjetControlService` erhält sämtliche Nicht-`None`-Ports;
  exakt diese Instanz wird an `AdminSocketServer`, `AdminHttpServer` und
  `AdminDaemon` gereicht. Google Inventory besitzt dafür eine öffentliche,
  fest an `STATE_DIRECTORY/api-token.yaml` gebundene Produktionsfactory;
  beliebige Credentialpfade bleiben am öffentlichen Konstruktor verboten.
  Cloudflare-Modi erzeugen den realen festen Fetcher und
  `RefreshingCloudflareAccessVerifier`. `AdminRuntime` schließt Owner,
  Authorities und Credential-FDs.
- **GREEN:** Der zunächst noch über das Produktmodul ausgeführte Test war nach
  der Assembly `1 passed in 1.30s`; der abschließende stärkere Test über das
  tatsächlich installierte Console-Script ist `1 passed in 29.85s`.

#### I1 — Readiness konnte einen bereits beendeten HTTP-Serve-Thread melden

- **Produktionsbruch:** Ein sofortiger Fehler in `serve_forever()` konnte mit
  `READY=1` konkurrieren.
- **Test:** `test_immediate_http_serve_failure_never_publishes_readiness`
  lässt den Serve-Pfad deterministisch vor Readiness ausfallen.
- **Beobachtetes RED:** `AdminDaemonStartupError` wurde nicht ausgelöst und
  Readiness konnte publiziert werden; dieser Test gehörte zum ersten Lauf mit
  `6 failed in 8.07s`.
- **Minimaler Fix:** `AdminHttpServer` publiziert eine explizite
  Serve-Startbarriere über `service_actions()`/`wait_serving()`. Der Daemon
  wartet bounded darauf und prüft Thread-Liveness sowie `_http_failure` vor
  dem Refresherstart und erneut unmittelbar vor `READY=1`.
- **GREEN:** Kein `READY=1`, Startupfehler und vollständiger Rollback; im
  finalen Task-Fokus grün.

#### I2 — Rollback schluckte Fehler und verwarf noch lebende Owner

- **Produktionsbruch:** Cleanupschritte konnten übersprungen werden; nach
  Join-Timeout wurden Live-Referenzen gelöscht und ein Startupfehler konnte
  unvollständige Ressourcen verschleiern.
- **Tests:**
  `test_partial_start_rollback_has_one_deadline_and_reports_live_cleanup`
  sowie die Retry-Assertions in den Shutdown-Tests.
- **Beobachtetes RED:** Der Rollback überschritt die Grenze bzw. verlor den
  Socketowner. Später blieben nach freigegebenem Worker und zweitem `stop()`
  noch Socket-Ressourcen eingetragen (`2 failed in 3.58s`); eine weitere RED-
  Assertion zeigte, dass ein schnell fehlschlagender Cleanup nicht in
  `incomplete_resources` erhalten wurde.
- **Minimaler Fix:** Startup-Rollback und Stop verwenden eine gemeinsame
  monotone Deadline. Jeder Owner läuft in einem daemonisierten,
  ownerkontrollierten Cleanup-Worker; Timeout und konkrete Cleanupfehler
  werden getrennt erfasst. HTTP-`shutdown`, Join, Drain, `server_close` und
  Authority-Close werden unabhängig versucht. Unvollständige Owner und ihre
  Referenzen bleiben für einen echten zweiten Cleanup-Versuch erhalten.
- **GREEN:** Deadline, Fehlercodes, Live-Referenzen und erfolgreicher Retry
  sind grün; die beiden Retry-Regressionen liefen zuletzt `2 passed in 2.50s`.

#### I3 — Shutdown konnte unbounded blockieren oder trotz Live-Worker Erfolg melden

- **Produktionsbruch:** Synchrones `socket.close()` konnte das gesamte
  Owner-Cleanup blockieren; nicht-daemonisierte Worker konnten einen bereits
  nonzero beendeten `run()`-Pfad im Python-Prozess festhalten.
- **Tests:**
  `test_permanently_blocked_socket_close_cannot_consume_owner_deadline`,
  `test_blocked_socket_shutdown_is_not_reported_as_success` und
  `test_blocked_real_effect_subprocess_exits_by_deadline_and_unlinks_socket`.
  Der Subprozess verwendet die reale Assembly und beide realen Transporte;
  nur der aufgerufene persistente Registry-Effekt wird absichtlich permanent
  blockiert.
- **Beobachtetes RED:** Der echte Subprozess endete nonzero, ließ nach der
  globalen Deadline aber den öffentlichen Unix-Socketnamen zurück
  (`1 failed in 6.97s`).
- **Minimaler Fix:** HTTP-, Socket- und JWKS-Owner werden parallel gegen eine
  gemeinsame Deadline geschlossen. Serve-/Adapter-/JWKS-Worker sind
  daemonisiert, verbleibende Worker ergeben nonzero. Der Socketserver entfernt
  nach seiner eigenen bounded Join-Grenze nur den exakt per Device/Inode und
  Service-UID attestierten Socketnamen, behält bei lebendem Worker jedoch
  Parent-FD, Identität und Workerreferenzen bis zu einem ehrlichen Retry.
- **GREEN:** Permanenter Effektblock beendet den Prozess bounded mit Status 1,
  sendet `STOPPING=1`, hinterlässt keinen Socketnamen und keine Ausgabe
  (`1 passed in 5.03s`). Die normalen Besitzerpfade enden Status 0.

#### I4 — unbekannte `kid`s konnten fortlaufend Cloudflare-Fetches auslösen

- **Produktionsbruch:** Wartende und aufeinanderfolgende Requests prüften nach
  Lockübernahme weder State-Generation noch ein globales negatives Budget.
- **Test:**
  `test_unknown_kids_share_one_refresh_and_one_global_negative_cooldown`
  startet konkurrierende unbekannte Kids und wiederholt unterschiedliche Kids
  innerhalb und nach dem festen Cooldown.
- **Beobachtetes RED:** Der Konstruktor kannte kein
  `unknown_kid_cooldown_seconds`; mehrere Requests konnten den Loader mehrfach
  aufrufen. Der Test gehörte zum ersten Lauf mit `6 failed in 8.07s`.
- **Minimaler Fix:** Unknown-Kid-Refresh ist Singleflight pro beobachteter
  Keyset-Generation. Nach Lockübernahme werden Generation, Closed-State und
  globales `retry_after` erneut geprüft. Erfolg und negativer Ausgang setzen
  ein monotones globales Cooldown-Budget; Fetch bleibt bounded und der letzte
  gültige aktuelle/vorherige Key-Satz bleibt atomar erhalten.
- **GREEN:** Genau ein Fetch im Zeitfenster, erneuter Fetch erst nach Ablauf;
  LKG- und Shutdown-Tests bleiben grün.

#### I5 — Wrappertests belegten keine Produktwirkung

- **Produktionsbruch:** Alte Tests verwendeten `None`-/`object()`-Owner und
  erklärten den permanenten `EX_CONFIG`-Abbruch zum Erfolg.
- **Tests:** Alle Lifecycle-Tests erhalten ihren Service jetzt aus
  `assemble_admin_runtime()` mit realen Ownern. Der installierte
  Console-Script-Subprozess belegt Credentials, `READY=1`, Unix-Attestation,
  authentisierten HTTP-Zugriff, den gemeinsamen Zustand beider Adapter,
  SIGTERM/`STOPPING=1`, Status 0, Deadline, Socketmodus/-UID, private
  State-Eigentümerschaft und leere, secretfreie Ausgabe. Der permanente
  Effektblock belegt Status 1, Deadline und Socket-/FD-Freigabe durch
  vollständige Prozessbeendigung.
- **Beobachtetes RED:** Neben dem C1-Timeout zeigte die erste Fixmatrix sechs
  echte Fehler. Nach den Lifecycle-Fixes blieb der installierte Produktpfad
  rot. Nach erster Assembly deckte der echte Blockadetest den verbliebenen
  Socketnamen auf. Die breite relevante Matrix fand anschließend noch die
  drei Vertragsabweichungen „Parent/Identität zu früh verworfen“ und
  „öffentlicher Loader akzeptiert beliebige Pfade“ (`3 failed, 952 passed`).
- **Minimaler Fix:** Keine Testservicefactory und keine Placeholder-Ports mehr;
  der Fixture-Ownergraph ist der produktive Ownergraph. Der Installtest baut
  das echte Wheel ohne Index/Dependencies in ein temporäres venv und startet
  dessen Console-Script ohne Worktree-Importpfad. Socket-Unlink und
  Cleanup-Metadatenfreigabe sind getrennt; Google-Produktionspfade sind an die
  feste systemd-State-Capability gebunden.
- **GREEN:** Die drei isolierten Vertragsregressionen plus beide echten
  Subprozesse: `5 passed in 8.09s` vor der Installtest-Verschärfung; finaler
  Task-Fokus: `27 passed in 24.84s`.

### Geänderte Produktionsflächen

- `src/codex_master/admin_assembly.py`: reale installierte Owner-, Credential-,
  Authority-, Portadapter- und Daemon-Assembly.
- `src/codex_master/admin_daemon.py`: installierter CLI-Pfad, Readiness-
  Barriere, Singleflight/Cooldown und deadline-basierter Rollback/Shutdown.
- `src/codex_master/admin_http.py`: explizite Serve-Startbarriere und bounded
  Prozessverhalten.
- `src/codex_master/admin_socket.py`: bounded Worker, ehrlicher Retry und
  sicherer früher Socket-Unlink.
- Google Inventory Loader/Store/Manager: ausschließlich die minimale feste
  `STATE_DIRECTORY`-Produktionsfactory; bestehende beliebige Testpfade bleiben
  privat.
- `systemd/codex-master-admin.service`: vollständiger Credentialvertrag um
  `admin-quota-evidence` ergänzt; die vorhandene Härtung bleibt unverändert.
- Tests: echte Assembly statt Placeholder-Owner, deterministische Lifecycle-
  Interleavings und zwei isolierte reale Subprozesse.

### Verifikation der Fixrunde

- RED-Ausgang: `6 failed in 8.07s` im neuen Taskfokus; danach gesonderte REDs
  für unstartbaren Produktprozess, zurückbleibenden Socket sowie verlorene
  Cleanup-Ressourcen.
- Isolierte finale Produkt-/Vertragsmatrix: `5 passed in 8.09s`.
- Finaler Taskfokus: `27 passed in 24.84s`.
- Breite relevante Admin-/Credential-/Google-/OpenAI-Matrix:
  `955 passed, 1 warning in 89.04s`.
- Vollsuite nach finalem Produktionscode:
  `6081 passed, 2 skipped, 3 failed, 636 subtests passed in 353.16s`.
  Die drei Fehler entsprechen der bereits vor dieser Fixrunde dokumentierten
  Repository-Baseline: zwei Admission-Deadline-Fälle waren direkt isoliert
  grün; der diff-fremde Server-Test bleibt isoliert wegen
  `fleet_recovery_pending` rot. Weder die betroffenen Produkt- noch Testdateien
  sind Teil dieses Diffs.
- Ruff auf allen geänderten Pythonflächen: grün.
- Formatcheck auf allen Task-/neuen Dateien: grün. Die bestehende, außerhalb
  der neuen Helperzeilen unformatierte Google-Inventory-Baseline wurde nicht
  mechanisch refaktoriert.
- Task-Mypy (`--follow-imports=skip`) für Assembly/Daemon/Transporte:
  `Success: no issues found in 4 source files`. Der erweiterte Lauf auf drei
  bestehenden Google-Dateien zeigt 48 Altbefunde, keine davon an den neuen
  Factoryzeilen; diese Baseline wurde nicht fremdrefaktoriert.
- `compileall` für vollständige `src`- und `tests`-Bäume: grün.
- `git diff --check`: grün.
- `systemd-analyze verify` parst die Unit und meldet erwartungsgemäß nur, dass
  `/usr/bin/codex-master-admin` im Worktree vor Systeminstallation noch nicht
  existiert. Die isolierte Wheel-Installation erzeugt und startet das
  Console-Script erfolgreich.
- Keine Secrets wurden geloggt oder in Argumente/Environment gelegt; die
  Subprozesse liefern leere Ausgabe und die Tests prüfen die verwendeten
  synthetischen Marker explizit auf Abwesenheit.

### Risiken und Restbedenken

Für C1/I1–I5 verbleibt keine bekannte funktionale Lücke. Restbedenken sind auf
die oben genannte diff-fremde Vollsuite-Baseline, die vorhandenen Google-Mypy-
Altbefunde und die naturgemäß erst bei Systeminstallation auflösbare
`/usr/bin`-Existenzprüfung begrenzt. Der installierte Pfad selbst ist durch die
isolierte Wheel-/Console-Script-Ausführung belegt.

### Commit

Basis dieser Fixrunde: `3908b00`.
Commit-Nachricht: `fix: complete masterjet admin daemon assembly`.
Der resultierende Hash steht in der Abschlussübergabe, da ein Commit seinen
eigenen Hash nicht stabil als Inhalt tragen kann.
