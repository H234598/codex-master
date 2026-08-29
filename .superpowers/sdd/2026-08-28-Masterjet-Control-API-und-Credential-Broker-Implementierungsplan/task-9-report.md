# Task 9 Report: Private Unix-Socket Control Adapter

Status: DONE

Base: `3d738e8`

Commit: `66f3902` (`feat: expose control service on private unix socket`)

## Implementierter Scope

- `src/codex_master/admin_socket.py`
  - privater Linux-`AF_UNIX`/`SOCK_STREAM`-Adapter
  - eine längenbegrenzte JSONL-Anfrage und eine längenbegrenzte Antwort pro
    Verbindung
  - `SO_PEERCRED` und injizierte Peer-Autorisierung vor Request-Parsing
  - `AdminSocketClient.call()` mit Ergebnisparität zu
    `MasterjetControlService.handle()`
  - sessiongebundenes `AdminSocketClient.put_secret_fd(session_id, fd)` nur
    über `SCM_RIGHTS`
  - typisierte, redaktierte `HiveProblemV1`-Fehler
- `src/codex_master/admin_service.py`
  - transportneutrale Nicht-JSON-Grenze
    `MasterjetControlService.put_secret(principal, session_id, secret)`
  - derselbe injizierte `SecretIngressPort` erhält
    `put_secret(session_id, secret, *, principal=...)`
  - Scope- und Step-up-Prüfung vor Owner-Aufruf
- `tests/test_admin_socket.py`
  - Integrations- und Security-Regressionen für Socket, Peer, JSONL und FD
- `tests/test_admin_service.py`
  - Service-Vertrag, Scopebindung, Typgrenze und identischer Buffer

Keine HTTP-, Daemon-, systemd- oder Task-10-Arbeit.

## Autorisierte Scope-Erweiterung

Ausgangsbasis hatte keinen sessiongebundenen Secret-Put. `SecretIngressPort`
bot nur `create_session()` und `resolve()`. Gemäß Brief wurde vor Erweiterung
`NEEDS_CONTEXT` gemeldet.

Ruling: Option B, transportneutral. `MasterjetControlService` und derselbe
Ingress-Owner werden erweitert; FD-Logik bleibt vollständig im Unix-Adapter.
Dadurch kann Task 10 später dieselbe Service-Grenze mit eigenständig
begrenztem Raw-Body verwenden. Es gibt keinen zweiten Ingress-Port und keinen
Secret-Pfad über `handle()`, `query()` oder `command()`.

## TDD-Nachweis

### Service RED

Command:

```bash
PYTHONPATH=src pytest tests/test_admin_service.py -k 'put_secret' -v
```

Resultat vor Produktion:

```text
5 failed, 37 deselected
AttributeError: 'MasterjetControlService' object has no attribute 'put_secret'
```

Ein erster Lauf ohne `PYTHONPATH=src` war kein gültiges RED: lokales
Worktree-Paket war nicht auf `sys.path`, daher Collection-Fehler
`ModuleNotFoundError: codex_master.admin_contracts`. Danach wurde der Runner
korrigiert und das erwartete Feature-RED beobachtet.

### Service GREEN

Command:

```bash
PYTHONPATH=src pytest tests/test_admin_service.py -k 'put_secret' -v
```

Resultat:

```text
5 passed, 37 deselected
```

### Socket RED

Command:

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py -v
```

Resultat vor Adapter:

```text
collection error
ModuleNotFoundError: No module named 'codex_master.admin_socket'
```

### Socket GREEN

Command:

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py -v
```

Resultat nach minimalem Adapter und Stream-Close-Korrektur:

```text
13 passed
```

Die Stream-Close-Korrektur drainiert nach einer frühen Ablehnung nur begrenzt
und ohne JSON-Parsing. Dadurch bleibt die typisierte Antwort erhalten, obwohl
die Peer-Autorisierung weiterhin vor jedem Parsing liegt.

### Security RED/GREEN: FD-Close bei CLOEXEC-Fehler

Self-Review fand einen Fehlerpfad: Scheiterte `set_inheritable()` für ein
empfangenes Duplicate, wurde es erst danach in die Close-Liste aufgenommen.

RED command:

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py::test_received_fd_is_closed_when_cloexec_enforcement_fails -v
```

RED result:

```text
1 failed
assert {16} == set()
```

Nach Aufnahme des FD in die Close-Liste vor CLOEXEC-Erzwingung:

```text
1 passed
```

## Verifikation

Relevante Regression vor finaler Gesamtverifikation:

```bash
PYTHONPATH=src pytest tests/test_admin_contracts.py tests/test_admin_service.py tests/test_admin_socket.py -v
```

Resultat vor zusätzlicher CLOEXEC-Regression:

```text
128 passed
```

Vollständige Repository-Suite nach CLOEXEC-Fix:

```bash
PYTHONPATH=src pytest -q
```

Resultat:

```text
5807 passed, 2 skipped, 3 warnings, 618 subtests passed in 136.99s
```

Finaler Wiederholungslauf nach mechanischer Ruff-Formatierung:

```text
5807 passed, 2 skipped, 3 warnings, 618 subtests passed in 128.73s
```

Finale Task-9-Zieltests:

```bash
PYTHONPATH=src pytest tests/test_admin_service.py tests/test_admin_socket.py -q
```

```text
56 passed in 2.13s
```

Separater Thread-Lifecycle-Check nach allen 14 Sockettests:

```text
14 passed in 1.83s
admin_threads []
```

Warnungen sind bestehende Deprecation-Warnungen aus PyGObject/asyncio sowie
eine bestehende `fork()`-Warnung in einem Credential-Service-Test. Keine neue
Warnung stammt aus Task 9.

Statische Checks:

```bash
git diff --check
PYTHONPATH=src python -m compileall -q \
  src/codex_master/admin_service.py \
  src/codex_master/admin_socket.py \
  tests/test_admin_service.py \
  tests/test_admin_socket.py
ruff check src/codex_master/admin_service.py src/codex_master/admin_socket.py \
  tests/test_admin_service.py tests/test_admin_socket.py
ruff format --check src/codex_master/admin_service.py \
  src/codex_master/admin_socket.py tests/test_admin_service.py \
  tests/test_admin_socket.py
mypy --follow-imports=skip --ignore-missing-imports \
  src/codex_master/admin_socket.py src/codex_master/admin_service.py
```

Resultat:

```text
git diff --check: exit 0
compileall: exit 0
ruff: All checks passed!
ruff format: 4 files already formatted
mypy: Success: no issues found in 2 source files
```

## Security Self-Review

### Socket und Peer

- Parent wird als echtes, server-eigenes Verzeichnis geprüft und auf `0700`
  gesetzt.
- Socket wird nach Bind als echter Socket, server-eigen und `0600` geprüft.
- Vorhandene Pfadobjekte werden nicht still entfernt oder überschrieben.
- `SO_PEERCRED` wird vor Empfang und Parsing gelesen.
- Autorität stammt ausschließlich aus dem injizierten
  `UnixPeerCredentials -> AdminPrincipalV1`-Resolver. Clientdaten können
  Principal oder Scopes nicht deklarieren.
- Resolverfehler werden zu `authority.peer_denied`; Fremdtexte erscheinen
  weder in Antwort noch Exception-Repräsentation.

### JSONL und Fehler

- Genau eine nichtleere, UTF-8-strikte JSON-Zeile mit EOF ist erlaubt.
- Mehrere Zeilen, Duplicate-Keys, unbekannte Felder, NaN/Infinity und
  Oversize werden fail-closed behandelt.
- Request und Reply haben getrennte harte Byte-Limits.
- Servicefehler verwenden ihr bereits validiertes `HiveProblemV1`.
- Adapter-/Parser-/Peerfehler erzeugen nur bekannte generische Problemcodes
  und konstante öffentliche Texte. Keine Tracebacks, Exception-Texte,
  Requestdaten oder Pfade werden gespiegelt.

### Secret FD

- Secret-Put-JSON enthält nur Schema, Transportart und Session-ID.
- Secretbytes werden nie über JSON, Base64, argv oder Environment akzeptiert.
- Secret-Put verlangt exakt einen per `SCM_RIGHTS` empfangenen FD; normale
  Calls verbieten Ancillary-FDs.
- `MSG_CMSG_CLOEXEC` plus explizites `set_inheritable(False)` schützen das
  Duplicate vor Vererbung.
- Alle empfangenen FDs werden bei Erfolg, Validierungsfehler,
  Ancillary-Fehler, mehrfachen FDs und CLOEXEC-Fehlern geschlossen.
- `fstat()` verlangt reguläre Datei, Eigentümer gleich Peer-UID und keine
  Group-/Other-Bits. `F_GETFL` verbietet `O_PATH` und write-only FDs.
- `st_size` und tatsächlich gelesene Bytes werden begrenzt; Metadaten werden
  nach dem Lesen erneut geprüft.
- Es wird nie ein Pfad aus dem FD aufgelöst oder erneut geöffnet. Damit folgt
  der Adapter nach Empfang keinem Symlink. Ob der Sender beim ursprünglichen
  Öffnen `O_NOFOLLOW` verwendete, lässt sich am bereits geöffneten FD unter
  Linux nicht nachträglich beweisen.
- Lesen erfolgt direkt per `readv()` in ein begrenztes `bytearray`. Nur ein
  `memoryview` erreicht den Service. Genutzte Bytes werden im `finally` bei
  Erfolg und Fehler überschrieben.

### Servicegrenze

- `put_secret()` akzeptiert nur exakt typisierte, nichtleere Bytes-like-Werte
  und eine begrenzte Tokenform für `session_id`.
- `fleet.secrets.ingress` und Step-up werden vor Owner-Aufruf verlangt.
- Der vollständige Principal wird an der Transportgrenze bestimmt; der
  validierte Subject wird dem bestehenden Sessionowner übergeben. Owner bleibt
  zuständig für Session, Account, Plan, Generation und Nonce.
- Owner-Ausnahmen werden ohne Fremdtext als validiertes Problem projiziert.

## Resthinweise

- Konkrete Peer-Identitäts-/Handshake-Policy bleibt bewusst injiziert. Der
  Adapter erzwingt, dass sie vor Parsing ausgeführt wird; Task 9 erfindet keine
  Deployment- oder Business-Policy.
- Bereits geöffnete FDs können ihre ursprüngliche Pfadauflösung nicht
  beweisen. Sicherheit basiert auf Kernelobjektprüfung via `fstat`, Peer-UID,
  privaten Mode-Bits, Flags, Größenlimit und fehlendem Reopen.
- Ein nach Crash zurückbleibender Socketpfad wird fail-closed nicht automatisch
  überschrieben. Operative Cleanup-/Daemonverdrahtung liegt außerhalb Task 9.

# Fixrunde 1/5 — 2026-08-29

Scope blieb auf `src/codex_master/admin_socket.py` und
`tests/test_admin_socket.py` begrenzt. `M1` (breite `BaseException`-Grenzen) ist
nach Review-Ruling ausdrücklich vertagt.

## C1 „Secret-Put konsumiert keinen stabil gebundenen Dateiinhalt“

### RED

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'reads_from_zero or ignores_shared_offset or requires_exactly_one_link or rejects_file_drift' \
  -v
```

```text
7 failed
```

Belegt wurden: vorpositionierter FD lieferte nur Suffix, geteilter Offset
beeinflusste Lesen, `st_nlink` 0/2 wurde akzeptiert und Shrink/Grow/Rewrite
zwischen erstem und zweitem Snapshot erreichte den Owner.

### GREEN

```text
7 passed
```

Erster `fstat()`-Snapshot prüft regulär, Peer-UID, private Mode-Bits,
`st_nlink == 1`, Read-only-Flags und Größenlimit. `preadv()` liest ab Offset 0
ohne Änderung des geteilten Dateioffsets, verlangt Snapshotgröße plus echtes
EOF und vergleicht danach
`dev/ino/mode/uid/gid/nlink/size/mtime_ns/ctime_ns` exakt.

## I1 „Ancillary-Fehler können nicht registrierte empfangene FDs leaken“

### RED

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'multi_rights or unknown_ancillary' -v
```

```text
4 failed
```

Belegt wurden reale FD-Leaks bei Fehler des ersten `set_inheritable(False)`
sowie bei unbekanntem CMSG vor einem späteren `SCM_RIGHTS`, jeweils im normalen
Empfang und beim Drain.

### GREEN

```text
4 passed
```

`_collect_fds()` scannt jetzt zuerst die vollständige Ancillary-Liste und
registriert alle vollständigen `SCM_RIGHTS`-Integer in der gemeinsamen
Ownership-Liste. Erst danach wird CLOEXEC auf allen neu übernommenen FDs
erzwungen und erst nach allen Versuchen ein gesammelter Validierungsfehler
ausgelöst. Empfang und Drain schließen dieselbe vollständige Liste.

## I2 „close() kehrt vor Ende aktiver Requests zurück“

### RED

```bash
PYTHONPATH=src pytest \
  tests/test_admin_socket.py::test_close_finishes_active_request_before_restart -v
```

```text
1 failed
hosts.calls == 2
```

Alter Request konnte nach `close()` und Restart noch einen Owner-Aufruf
ausführen.

### GREEN

```text
1 passed
```

Listenergeneration, Stop-Event und aktiver Connection-Socket werden explizit
geführt. `close()` schließt Listener, fährt aktive Connection herunter, wartet
ohne Timeout auf tatsächliches Threadende und räumt Zustand erst danach auf.
Restart erzeugt genau eine neue Generation; alter Request führt keinen späten
Owner-Aufruf aus.

## I3 „Geprüfter Socket-Parent ist nicht an bind() gebunden“

### RED

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'parent_swap or parent_replacement or verifies_server_peer' -v
```

```text
3 failed
```

Beide Parenttausch-Szenarien starteten erfolgreich. Client besaß keine
`expected_server_uid`-Grenze und konnte den Server daher nicht vor Send prüfen.

### GREEN

```text
3 passed
```

Parent wird ab `/` komponentenweise mit `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`
geöffnet beziehungsweise relativ zum jeweils gepinnten FD erzeugt. Voller
`fstat()`-Snapshot bleibt bis Cleanup erhalten; Bind, Leaf-Stat und Unlink
arbeiten relativ zum Parent-FD. Kanonischer Parent wird vor und nach Bind gegen
dieselbe Invariante `dev/ino/mode/uid/gid/nlink` geprüft. Client liest direkt
nach `connect()` `SO_PEERCRED` und vergleicht Server-UID vor jedem Byte und vor
`SCM_RIGHTS`; der falsche Server erhielt im RED/GREEN-Test nur EOF und keine
Ancillary-Daten.

## Abschlussverifikation Fixrunde

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py tests/test_admin_service.py -q
ruff check src/codex_master/admin_socket.py tests/test_admin_socket.py
ruff format --check src/codex_master/admin_socket.py tests/test_admin_socket.py
mypy --follow-imports=skip --ignore-missing-imports \
  src/codex_master/admin_socket.py src/codex_master/admin_service.py
python -m compileall -q src tests
git diff --check
```

```text
Task-9-Tests: 71 passed in 3.06s
Ruff changed files: All checks passed
Ruff format: 2 files already formatted
Mypy: Success: no issues found in 2 source files
Compileall: exit 0
git diff --check: exit 0
```

Erster vollständiger Lauf `PYTHONPATH=src python -m pytest -q` endete mit
Exit 0. Kontrolllauf ergab:

```text
2 failed, 5820 passed, 2 skipped, 3 warnings, 618 subtests passed in 180.48s
```

Beide Fehler liegen unverändert außerhalb Task-9-Scope in
`tests/test_admission_runtime.py`: erwartete Gatefehler wurden wegen der
laufzeitabhängigen Test-Deadline als `admission_expired` klassifiziert. Direkte
Wiederholung unmittelbar danach:

```bash
PYTHONPATH=src pytest \
  tests/test_admission_runtime.py::test_runtime_missing_hive_bindings_denies_and_never_executes \
  tests/test_admission_runtime.py::test_runtime_gate_exception_and_unknown_completion_fail_closed \
  -q
```

```text
2 passed in 1.11s
```

Repository-weites Ruff meldet drei vorbestehende, unberührte Befunde in
`src/codex_master/queen_runtime.py`, `tests/test_emergency_queen.py` und
`tests/test_resource_cgroup.py`. Geänderte Dateien sind sauber.

## Security Self-Review Fixrunde

- C1: Owner erhält nur Inhalt, der an dasselbe offene reguläre Dateiobjekt,
  Offset 0, exakte Snapshotgröße, EOF und stabilen Vor-/Nach-Snapshot gebunden
  ist. Caller-Offset bleibt unverändert. Bufferzeroisierung und FD-Close-Pfade
  bleiben erhalten.
- I1: Kein erkannter `SCM_RIGHTS`-FD verlässt Ownership vor vollständiger
  Ancillary-Auswertung. CLOEXEC- und unbekannte-CMSG-Fehler schließen alle
  übernommenen FDs auch im Drain.
- I2: Kein alter Requestthread überlebt erfolgreiches `close()`; Listener und
  aktive Connection werden vor unbeschränktem Join beendet. Neue Generation
  startet erst aus vollständig geräumtem Zustand.
- I3: Server bindet nicht mehr über einen nach Prüfung frei auflösbaren Parent.
  Gepinnter Parent-FD und kanonischer Identitäts-Recheck erkennen Tausch vor
  sowie nach Bind. Client gibt ohne erwartete Server-UID weder JSON noch
  Secret-FD frei.
- Problemantworten bleiben typisiert und redigiert. Keine neue Echo-,
  Traceback-, HTTP-, Daemon- oder Task-10-Fläche entstand.
- `M1` bleibt entsprechend Ruling außerhalb dieser Fixrunde.

# Fixrunde 2/5 — 2026-08-29

Scope blieb auf `src/codex_master/admin_socket.py` und
`tests/test_admin_socket.py` begrenzt. Gegenstand war ausschließlich das neue
Fix1-Re-Review-Finding I4. `M1` bleibt ausdrücklich deferred.

## I4 „Unbegrenztes join() kann Shutdown dauerhaft blockieren“

### Root Cause

`close()` schloss Listener und aktiven Connection-Socket, rief danach aber
`thread.join()` ohne Timeout auf. Socket-Shutdown beendet blockiertes
Transport-I/O, nicht bereits laufenden synchronen Code im Peer-Authorizer,
`MasterjetControlService.handle()` oder einem injizierten Owner.

### RED

Zwei echte Requestpfade wurden unabhängig vom Socket auf einem Test-Event
blockiert: einmal der Peer-Authorizer, einmal `hosts.list` im injizierten
Host-Owner hinter dem realen Service.

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'bounded_and_fail_closed' -v
```

```text
2 failed
beide close()-Threads lebten nach 1.5 Sekunden weiter
```

Die Tests lösen ihr Blockade-Event erst im Cleanup. Damit reproduzieren sie
den unbegrenzten Join, ohne den Pytest-Prozess selbst dauerhaft festzuhalten.

### GREEN

```text
2 passed in 3.20s
```

Der Adapter besitzt jetzt eine separate harte Shutdowngrenze von einer
Sekunde. `close()` setzt weiterhin generationseigenes Stop-Event, schließt
Listener und fährt den aktiven Socket herunter. Danach wartet es höchstens bis
zur Grenze auf den Worker. Lebt dieser weiter, wird exakt ein code-only
`AdminSocketError` mit `control.socket_shutdown_incomplete` ausgelöst.

Auf diesem Fehlerpfad bleiben Thread, Generation, Parent-FD, Socketidentität
und Leaf registriert. `start()` bleibt dadurch fail-closed blockiert. Nach
Eventfreigabe beendet sich derselbe Worker; ein zweites `close()` wartet erneut
begrenzt, sieht das tatsächliche Threadende und finalisiert Socket/Parent/
Generation idempotent. Kein Thread wird als Daemon abgetrennt.

Bestehender Normalpfad:

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py -k 'close_' -v
```

```text
3 passed in 2.68s
```

Damit bleiben normaler Close/Restart, genau eine neue Generation und kein
später Owner-Aufruf nach erfolgreichem Close belegt.

## Abschlussverifikation Fixrunde 2

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py tests/test_admin_service.py -q
ruff check src/codex_master/admin_socket.py tests/test_admin_socket.py
ruff format --check src/codex_master/admin_socket.py tests/test_admin_socket.py
mypy --follow-imports=skip --ignore-missing-imports \
  src/codex_master/admin_socket.py src/codex_master/admin_service.py
python -m compileall -q src/codex_master/admin_socket.py \
  tests/test_admin_socket.py
git diff --check
PYTHONPATH=src python -m pytest -q
```

```text
Task-9-Zielsuite: 73 passed in 6.05s
Ruff: All checks passed
Ruff format: 2 files already formatted
Mypy: Success: no issues found in 2 source files
Compileall: exit 0
git diff --check: exit 0
Vollsuite: 5824 passed, 2 skipped, 3 warnings,
            618 subtests passed in 226.10s
```

Die drei Warnungen sind dieselben vorbestehenden PyGObject-/asyncio-/fork-
Warnungen wie in Fixrunde 1. Keine Warnung stammt aus Task 9.

## Security Self-Review Fixrunde 2

- Ein synchron blockierter Callback kann `close()` nicht mehr unbegrenzt
  festhalten. Die maximale Worker-Wartezeit pro Aufruf ist hart begrenzt.
- Timeout wird nicht als Erfolg dargestellt: Problem ist typisiert,
  redigiert und enthält nur `control.socket_shutdown_incomplete`.
- Unvollständiger Shutdown löscht weder Socketidentität noch Parent-FD oder
  Generation. Dadurch kann kein Restart parallel zum alten Worker entstehen.
- Erst nach nachgewiesenem Threadende räumt erfolgreicher Close den Zustand
  auf. Damit garantiert erfolgreicher Close weiterhin keinen alten Thread und
  keinen nachfolgenden Effekt dieser Generation.
- Python-Threads werden nicht unsicher extern abgebrochen und nicht als
  Daemon detacht. Für garantierten harten Prozessausstieg bei einem Owner, der
  niemals zurückkehrt, bleibt ein endlicher Owner-Timeout oder kooperative
  Cancellation an der Ownergrenze erforderlich; das liegt außerhalb des
  minimalen I4-Transportvertrags.
- C1/I1/I2/I3 bleiben unverändert geschlossen. Keine HTTP-, Daemon-, Task-10-
  oder Businesslogik-Fläche wurde ergänzt. `M1` bleibt deferred.

# Fixrunde 3/5 — 2026-08-29

Scope blieb auf `src/codex_master/admin_socket.py` und
`tests/test_admin_socket.py` begrenzt. Keine Scope-Erweiterung, kein
Admin-Service-, HTTP-, Daemon- oder Task-10-Eingriff war nötig. Anlass war
Usage-Whole-Review Important 2: Same-UID, Socketpfad und `SO_PEERCRED` allein
authentisieren keinen lokalen sensitiven Aufrufer.

## Protokollruling

Jede produktive `AdminSocketServer`-Connection muss vor Request-JSON oder
`SCM_RIGHTS` einen versionierten gegenseitigen HMAC-SHA256-Handshake
abschließen. Damit braucht der Adapter keine fehleranfällige lokale
Action-/Scopeklassifikation und erfindet keine Businesslogik.

Der Server sendet eine frische 32-Byte-Servernonce und seine
`pid/uid/gid`-Identität. Der Client prüft unmittelbar nach `connect()` erneut
`SO_PEERCRED` auf genau derselben Socketinstanz, erzeugt eine frische
32-Byte-Clientnonce und beweist Schlüsselbesitz. Der Server bestätigt seinen
Schlüsselbesitz erst nach erfolgreichem `compare_digest()` des Clientbeweises.
Beide Beweise verwenden getrennte Domains über dasselbe kanonische binäre
Transcript:

```text
"codex-master/admin-socket/attestation/transcript\0"
+ struct.pack("!BIII", version, server_pid, server_uid, server_gid)
+ server_nonce[32]
+ client_nonce[32]
```

Client- und Serverbeweis verwenden zusätzlich getrennte
`client-proof\0`-/`server-proof\0`-Domains. Frische Server- und Clientnonce
binden jeden Beweis an genau eine Connection; eine aufgezeichnete Response
scheitert am nächsten Challenge-Transcript.

`local_attestation_verifier(key_fd)` liefert exakt den von Usage erwarteten
Callback `(pid, uid, gid, socket) -> bool`. Er vergleicht die übergebenen
Peerwerte nochmals mit `SO_PEERCRED` derselben Socketinstanz und sendet vor
erfolgreicher Peerprüfung kein Byte.

Der Schlüssel kommt ausschließlich als geliehenes, bereits geöffnetes FD in
Server, Client oder Verifier. Kein argv-, env-, Config-, JSON- oder Logpfad
wurde ergänzt. Das FD muss owner-only, regulär, read-only, single-link und
zwischen 32 und 1024 Byte groß sein. Lesen erfolgt unabhängig vom geteilten
Dateioffset mit `preadv()` ab Offset 0, exaktem EOF und stabilem
Vor-/Nach-Snapshot. Der transiente `bytearray` wird auf jedem Pfad zeroisiert;
das geliehene FD wird nicht geschlossen.

Handshake-Frames sind strikt eindeutige, exakt typisierte JSONL-Objekte bis
2048 Byte. Malformed JSON, doppelte Keys, falsche Version, falsche Feldmenge,
Nonce/Proof-Fehler, Timeout, Ancillary-Daten und Replay werden fail-closed als
redigiertes `control.attestation_required` behandelt. Empfangene Rights werden
vor Fehlerweitergabe übernommen und geschlossen. Secret- oder Step-up-FDs
werden clientseitig erst nach bestätigtem Serverbeweis gesendet.

## RED

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py -k 'attestation' -v
```

```text
3 failed, 9 errors, 33 deselected
```

Fehlend waren Constructor-Dependency, öffentlicher Usage-Verifier und beide
Handshake-Seiten. Ohne Server-Key wartete ein Client bis Timeout, statt
`control.attestation_required` zu erhalten. Replay-, falscher-Key-,
Frame-/Versions-, Partial-I/O-, Connection-Identity-, Timeout-/Redaction- und
Shutdownfälle konnten den neuen Vertrag deshalb nicht erfüllen.

Vor Produktcode wurde die Testmatrix chirurgisch konsolidiert: ein
parametrisierter adversarial-frame-Test, gemeinsame unabhängige
Transcript/Proof-Helper und ein einziger byteweise fragmentierter
Produktionspfad für Challenge, Response und Ack. Sicherheitsinvarianten
blieben erhalten; redundante Fake-Listener entfielen.

## GREEN

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'attestation or usage_verifier' -v
```

```text
13 passed, 31 deselected
```

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py tests/test_admin_service.py -q
```

```text
86 passed in 6.43s
```

Belegt sind erfolgreicher Usage-kompatibler Callback, fehlender und falscher
Key ohne Secret-FD-Freigabe, Replayabwehr, malformed/duplicate/version/
nonce/oversize, byteweise fragmentierte Frames in beide Richtungen,
Connection-Identity-Swap, typisierter redigierter Timeout sowie bounded Close
während eines partiellen Handshakes. Alle bestehenden Task-9-Tests nutzen nun
explizit das private Test-Key-FD; unauthentisierte Autorisierungs- und
Peer-Denial-Tests bleiben vor dem Handshake unverändert fail-closed.

## Abschlussverifikation Fixrunde 3

```bash
ruff check src/codex_master/admin_socket.py tests/test_admin_socket.py
ruff format --check src/codex_master/admin_socket.py tests/test_admin_socket.py
mypy --follow-imports=skip --ignore-missing-imports \
  src/codex_master/admin_socket.py src/codex_master/admin_service.py
python -m compileall -q src/codex_master/admin_socket.py \
  tests/test_admin_socket.py
git diff --check
PYTHONPATH=src python -m pytest -q
```

```text
Ruff: All checks passed
Ruff format: 2 files already formatted
Mypy: Success: no issues found in 2 source files
Compileall: exit 0
git diff --check: exit 0
Vollsuite: 2 failed, 5876 passed, 2 skipped, 3 warnings,
            618 subtests passed in 232.50s
```

Die zwei Vollsuitefehler sind die bereits in Fixrunde 1 beobachteten,
laufzeitabhängigen `tests/test_admission_runtime.py`-Deadline-Flakes:

```text
test_runtime_missing_hive_bindings_denies_and_never_executes
test_runtime_gate_exception_and_unknown_completion_fail_closed
```

Beide wurden im Anschluss isoliert wiederholt:

```bash
PYTHONPATH=src pytest \
  tests/test_admission_runtime.py::test_runtime_missing_hive_bindings_denies_and_never_executes \
  tests/test_admission_runtime.py::test_runtime_gate_exception_and_unknown_completion_fail_closed \
  -q
```

```text
2 passed in 0.56s
```

## Security Self-Review Fixrunde 3

- Same-UID, Socketpfad und Peercredentials autorisieren allein keine
  produktive Admin-Connection mehr. Ohne gültigen injizierten Key endet sie
  vor Request oder FD-Transfer mit `control.attestation_required`.
- Gegenseitige, domainseparierte HMAC-Beweise binden Version, beobachtete
  Serveridentität und beide frischen Nonces. `compare_digest()` vermeidet
  normalen früh abbrechenden Proofvergleich; Replay über neue Connections
  scheitert am neuen Transcript.
- Der Usage-Callback vertraut übergebenen `pid/uid/gid` nicht blind, sondern
  liest `SO_PEERCRED` erneut auf genau der Socketinstanz vor jedem Send.
- Private Keybytes verlassen nie das geliehene FD-/Buffer-Modell. Offset,
  Typ, Owner, Mode, Linkzahl, Größe, EOF und stabiler Dateisnapshot werden
  geprüft; transiente Buffer werden best-effort zeroisiert.
- Handshake-Parser und -Frames sind bounded, exact-field, duplicate-safe und
  timeoutgebunden. Private Payloads werden weder gespiegelt noch geloggt;
  Fehler bleiben code-only und redigiert.
- Erfolgreicher Shutdown beendet auch partielle Handshakes. Fixrunde-2-
  Semantik bleibt erhalten: bounded `close()`, kein falscher Erfolg bei noch
  lebendem Worker, kein Restart über unvollständige Generation.
- C1/I1/I2/I3/I4 bleiben geschlossen. `M1` bleibt entsprechend Ruling
  deferred.

# Fixrunde 4/5 — 2026-08-29

Scope blieb auf `src/codex_master/admin_socket.py` und
`tests/test_admin_socket.py` begrenzt. Gegenstand waren ausschließlich I5 und
M2 aus dem Re-Review nach `634dd22`; deferred M1 wurde nicht berührt.

## I5 „Attestation vor Principal/Policy“

### RED

Bestehende Missing-/Wrong-Key-, malformed-Handshake-, Peer-Denial- und
Lifecyclefälle erhielten einen seiteneffektbehafteten Principal-Callback.
Zusätzlich belegt `_receive_frame`, dass vor erfolgreicher Attestation keine
Application-Request-Verarbeitung beginnt. Host-Service und Secret-Ingress
zählen ihre Owneraufrufe unabhängig.

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'missing_attestation_key or wrong_attestation_key or \
      invalid_attestation_key_fd or attestation_rejects_invalid_bounded_frames or \
      usage_compatible_attestation or peer_authority or blocked_authorizer or \
      close_finishes_active' -q
```

```text
14 failed, 2 passed
```

Erstes erwartetes Failure: fehlender Key rief Principal einmal auf. Der
RED-Sammellauf ließ nach frühem Assertion-Failure den absichtlich blockierten
Non-Daemon-Authorizer-Worker stehen; der exakte pytest-Prozess wurde beendet.
Spätere GREEN-Läufe hinterließen keinen pytest-Prozess.

### GREEN

`AdminSocketServer._handle()` führt jetzt
`SO_PEERCRED → mutual attestation → principal → request frame/parse → service`
aus. Missing Key, falscher Proof und malformed Handshake erreichen weder
Principal/Policy, Application-Request-Verarbeitung, Service noch
Secret-Ingress-Owner. Nach gültiger Attestation läuft Principal genau einmal.

Die neue Reihenfolge machte eine Stream-Race sichtbar: direkt nach dem
Serverproof konnte eine anschließende Peer-Denial-Antwort im selben `recvmsg()`
landen. Der Attestation-Reader liest deshalb framegenau bis zum ersten
Newline-Byte. Wireformat, Limits und Handshakezustände bleiben unverändert;
kein Protokollfeld und kein Roundtrip kam hinzu. Blocked-Authorizer- und
Close/Restart-Regression authentisieren nun zuerst und belegen danach
unverändert bounded, fail-closed Shutdown.

## M2 „Key-FD-Fehlercode“

Server-, Client- und Usage-Verifier-Factory trennen Typ-/Negativprüfung von
allgemeiner Socketkonfiguration. Typfremde und negative FDs liefern nun wie
fehlende, geschlossene, unlesbare oder kryptografisch falsche Key-FDs nur den
code-only Problemcode `control.attestation_required`. Repr und String spiegeln
keinen übergebenen Marker.

## Verifikation Fixrunde 4

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py tests/test_admin_service.py -q
ruff check src/codex_master/admin_socket.py tests/test_admin_socket.py
ruff format --check src/codex_master/admin_socket.py tests/test_admin_socket.py
mypy --follow-imports=skip --ignore-missing-imports \
  src/codex_master/admin_socket.py src/codex_master/admin_service.py
python -m compileall -q src/codex_master/admin_socket.py \
  tests/test_admin_socket.py
git diff --check
```

```text
Task-9-/Service-Suite: 88 passed in 6.51s
Ruff: All checks passed
Ruff format: 2 files already formatted
Mypy: Success: no issues found in 2 source files
Compileall: exit 0
git diff --check: exit 0
```

Kein zusätzlicher Vollsuite-Endloslauf: Fix ist auf zwei Dateien und zwei
Reviewbefunde begrenzt; vorherige Fixrunde belegte 5876 grüne Tests mit nur den
bekannten isoliert grünen `admission_runtime`-Deadline-Flakes. Ein begonnener
Kontrolllauf wurde auf Koordinatoranweisung nach 3 % ohne Failure beendet. M1
bleibt deferred und unverändert.

# Fixrunde 5/5 — 2026-08-29

Scope blieb auf `src/codex_master/admin_socket.py` und
`tests/test_admin_socket.py` begrenzt. Gegenstand war ausschließlich der nach
Fixrunde 4 verbliebene offene Teil von M2: positive, bereits bei
Factory-Erzeugung ungültige Key-FDs in `local_attestation_verifier()`.

## M2 „Positive ungültige Key-FDs an der Verifier-Factory“

### Root Cause und RED

Die Factory prüfte bisher nur Typ und Negativwert. Geschlossene positive,
write-only oder während des stabilen Ladevorgangs aus dem privaten Modus
gedriftete FDs lieferten daher zunächst einen Callback. Erst ein späterer
Callback-Aufruf lud das FD und reduzierte jeden Loaderfehler auf `False`.

Vor Produktion wurden drei Factory-Construction-Fälle ergänzt: geschlossener
positiver FD, write-only FD und Mode-Drift `0600 -> 0644` zwischen erstem und
zweitem `fstat()`.

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'usage_verifier_factory_rejects' -q
```

```text
3 failed, 46 deselected
Failed: DID NOT RAISE AdminSocketError
```

Alle Fälle verlangten denselben validierten, code-only Fehler
`control.attestation_required`, redigierte `str`/`repr`, unveränderte
FD-Anzahl und bei noch offenem FD erhaltene Caller-Ownership.

### GREEN und Lifecycle

`local_attestation_verifier()` lädt und validiert das geliehene FD nun einmal
beim Factorybau über den bestehenden stabilen `_load_attestation_key()`.
Loaderfehler werden dort zu `AdminSocketError(control.attestation_required)`
projiziert. Der ausschließlich für diese Probe erzeugte `bytearray` wird im
`finally` sofort überschrieben und weder gespeichert noch vom Callback
geschlossen.

Der Callback lädt das weiterhin geliehene FD bei jedem Handshake erneut.
Dadurch kann derselbe Verifier wiederholt authentisieren; Drift nach dem
Factorybau wird nicht durch einen langfristigen Secret-Snapshot verdeckt,
sondern endet fail-closed mit `False`. Separate Regressionen belegen zwei
erfolgreiche Handshakes derselben Factory, erhaltenes Borrowing und
post-construction Mode-Drift vor Principal/Policy.

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py \
  -k 'usage_verifier_factory_rejects or usage_compatible_attestation or \
      usage_verifier_rejects or usage_verifier_rereads' -q
```

```text
6 passed, 44 deselected in 1.30s
```

Kein Wireformat, Handshakefeld, Roundtrip, Fehlercode oder öffentliche
Callbacksignatur änderte sich.

## Verifikation Fixrunde 5

```bash
PYTHONPATH=src pytest tests/test_admin_socket.py tests/test_admin_service.py \
  tests/test_admin_secret_ingress.py -q
ruff check src/codex_master/admin_socket.py tests/test_admin_socket.py
ruff format --check src/codex_master/admin_socket.py tests/test_admin_socket.py
PYTHONPATH=src mypy --follow-imports=skip --ignore-missing-imports \
  src/codex_master/admin_socket.py src/codex_master/admin_service.py
python -m compileall -q src/codex_master/admin_socket.py \
  tests/test_admin_socket.py
git diff --check
```

```text
Task-9-/Service-/C5-Reserve-Port-Suite: 97 passed in 7.91s
Ruff: All checks passed
Ruff format: 2 files already formatted
Mypy: Success: no issues found in 2 source files
Compileall: exit 0
git diff --check: exit 0
```

Auf Koordinatoranweisung war keine erneute Vollsuite nötig. Produkt- und
Testfix sind Commit `4d20330` (`fix: validate socket attestation credential
eagerly`). M1 bleibt separat deferred und unverändert.

## Security Self-Review Fixrunde 5

- Factoryfehler für positive ungültige FDs sind nun typed, code-only und
  redigiert; FD-Wert, Pfad, Keybytes und fremder Exceptiontext werden nicht
  gespiegelt.
- Die Factory übernimmt keine FD-Ownership und dupliziert kein FD. Offene
  Caller-FDs bleiben auf Erfolg und Fehler offen; geschlossene Eingänge
  erzeugen keine neuen FDs und keinen Leak.
- Probe-Keybytes leben nur im lokalen mutablen Buffer und werden auf Erfolg
  sowie Fehler überschrieben. Der Closure-State enthält nur das geliehene FD,
  keine langfristige immutable Secretkopie.
- Jeder Callback validiert und liest erneut stabil per Offset 0. Wiederholte
  Handshakes bleiben möglich; Drift nach Construction schlägt geschlossen
  fehl und erreicht keinen Principal/Policy-Callback.
- Frühere C1/I1/I2/I3/I4/I5 sowie frame-exaktes Lesen bleiben unverändert.
