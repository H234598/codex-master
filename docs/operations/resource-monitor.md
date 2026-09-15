# The Hive Resource Monitor (H4)

Der Resource Monitor ist ein separater, optionaler Systemd-User-Dienst für
The Hive. Er veröffentlicht fortlaufend bootgebundene V2-Ressourcenevidenz im
autorisierten zentralen Hive-State-Store. Diese Seite ist die kompakte,
gepflegte Überführung des H4-Abschnitts aus dem README der Basisrevision
`b5def7d6156d7862606a0edcbd7226652cf4833f`; sie ist keine
Aktivierungsanleitung.

## Auslieferungs- und Laufzeitvertrag

- Der eingecheckte Dienst heißt
  [`the-hive-resource-monitor.service`](../../systemd/user/the-hive-resource-monitor.service).
  Er läuft in `the-hive.slice` und verwendet den attestierten Einstiegspunkt
  `bin/the-hive-resource-monitor` aus einer Runtime-Generation.
- Der Einstiegspunkt verlangt genau drei vom Dienst gebundene Werte:
  Runtime-Root, Generation und Manifest-Digest. Ein argumentloser Aufruf ist
  kein unterstützter Betriebsweg und schlägt fehl.
- Der Monitor verwendet nur den zentral zusammengesetzten, autorisierten
  Hive-State-Store. Er veröffentlicht kanonische
  `resources/resource-evidence-v2.json`-Dokumente; der Loop plant Abtastungen
  im Ein-Sekunden-Takt. Die Evidenz kann `warming`, `unavailable` oder `ready`
  sein. `ready` ist daher keine Annahme aufgrund eines vorhandenen Unit-Files.
- Die Runtime-Image-Definition führt den Einstiegspunkt sowie Dienst und Slice
  als attestierte H4-Artefakte. Die technische State-Pfadkomponente
  `codex-master-mcp` ist dabei ein bestehender Laufzeitvertrag, nicht der
  aktive Produktname.

Alle direkte Bedienung erfolgt über die von der Deployment-Ownerin bestimmte,
attestierte Laufzeitschnittstelle. Der eingecheckte
[`bin/the-hive-mcp`](../../bin/the-hive-mcp) benötigt selbst
Release-Bindungsargumente und ist deshalb kein portabler Checkout-Befehl. Die
Quellschnittstelle kennt die datenarme Abfrage `resource-monitor-status` und
die mutierende Operation `install-resource-monitor`; diese Seite liefert
bewusst keinen Aufruf für letztere.

## Status und Owner-Grenze

Allein die Auslieferung aktiviert den Dienst nicht. Die normale
Runtime-Image-Installation materialisiert die H4-Unit-Paarung nicht in das
User-Systemd-Verzeichnis und startet den Monitor nicht implizit. Die
Materialisierung und das Aktivieren gehören zur ausdrücklich autorisierten
Lifecycle-Ownerin. Der Slice wird dabei nicht separat aktiviert oder gestartet.

Die Statusprojektion bewertet mindestens:

- ob Monitor- und Slice-Unit als reguläre, passende Dateien materialisiert
  sind;
- ob der Monitor geladen und aktiv ist, beide `FragmentPath`-Werte real sind
  und der Monitor tatsächlich Kind des Slice ist; und
- ob eine frische, gültige Ressourcenevidenz vorliegt.

Ein inaktiver, kinderloser Slice ist nur dann der erwartete Zustand, wenn sein
Fragment real und die Unit materialisiert ist. Fehlende oder synthetische
Fragmente, fremde bzw. gemischte Unit-Dateien oder nicht frische Evidenz sind
Blocker. Die Ownerin soll diese Klassifikation und die
Deployment-spezifische, autorisierte Diagnoseoberfläche verwenden, statt
Runtime-Dateien, State oder Units manuell zu verändern.

Die öffentliche Status- und Fehlerprojektion ist datenarm: Sie liefert
Klassifikationen, Fehlercodes und Rückgabecodes, nicht rohe Systemd-Ausgaben
oder lokale Zielpfade.

## Installation und Wiederherstellung

Die implementierte mutierende Lifecycle-Operation arbeitet mit dem
Service-/Slice-Paar, einer kooperativen `flock`-Sperre und
release-attestierten Quellen. Vor einer Mutation prüft sie reguläre Dateien,
no-follow-Dateideskriptoren, Dateiattribute und die Zielverzeichniskette;
unsichere Symlinks oder bereits existierende gruppen-/welt-schreibbare
Zielverzeichnisse werden abgelehnt. Die finale
`~/.config/systemd/user`-Komponente muss der ausführenden Benutzerin gehören
und darf nicht gruppen- oder welt-schreibbar sein. Geteilte Sticky-Parents
sind nicht dasselbe wie ein vertrauenswürdiges finales Ziel.

Beide Units werden vor der ersten Mutation vorbereitet und geprüft. Vor jedem
externen Systemd-Schritt werden das gepinnte Zielverzeichnis, die gehaltene
Sperre und die installierten Unit-Identitäten erneut geprüft. Die Operation
lädt den User-Manager erst danach neu und aktiviert ausschließlich
`the-hive-resource-monitor.service`.

Die Paarersetzung ist nicht atomar: Ein Absturz zwischen den einzelnen
Dateioperationen kann eine gemischte Paarung hinterlassen, und das
Prozessjournal existiert dann nicht mehr. Deshalb nicht aus unbekanntem
UnitFile-/Active-State raten oder Pfade und Dateien nachbauen. Die aktuelle
Statusklassifikation, geprüfte Dateisystemevidenz und autorisierte manuelle
Recovery durch die Lifecycle-Ownerin sind in diesem Fall erforderlich.

Die Sperre serialisiert kooperierende Installer-Prozesse. Manipulation durch
dieselbe UID, root oder den User-Systemd-Namensraum außerhalb dieser Grenze ist
kein adversarielles Mutex-Schutzversprechen.

## Trust Boundaries

Der Dienst ist eng eingeschränkt:

- `ProtectHome=tmpfs` und `PrivatePIDs=yes` verbergen fremde Home- bzw.
  Prozessdaten; `ProtectSystem=strict`, `NoNewPrivileges=yes` und ein leeres
  `CapabilityBoundingSet` reduzieren weitere Rechte.
- `IPAddressDeny=any` und `RestrictAddressFamilies=AF_UNIX` erlauben keine
  Netzverbindung. Der Dienst liest nur die im Unit-File festgelegten
  Interpreter-, Sensor- und `/proc`-Quellen sowie die attestierten
  Runtime-Artefakte.
- `BindReadOnlyPaths` bindet nur Monitor-Layout, Quellbaum, feste Kataloge und
  zentralen Hive-State lesbar ein. `ReadWritePaths` begrenzt Schreibzugriff
  auf dessen `resources`-Unterbaum und die bestehende Hive-State-Sperre.

Ein Runtime-Manifest ersetzt keine native Hook-Trust-Entscheidung. Fehlt
frische, kanonische V2-Hook-Abdeckung, meldet der Status
`manual_hook_trust_or_new_session_required`. Nur eine neue reguläre
Codex-Sitzung nach einer expliziten Benutzerin-Trust-Entscheidung kann diese
Abdeckung erzeugen; kein Monitor-Befehl automatisiert Trust oder schreibt
synthetischen nativen Zustand.

## Verweise

- [Operations Runbook](runbook.md) für die allgemeinen Diagnose- und
  Mutationsgrenzen
- [Recovery](recovery.md) für den evidenzbasierten Recovery-Rahmen
- [The Hive Security](../security/hive-security.md) für übergreifende
  Trust-Boundaries
- [Unit-Quelle](../../systemd/user/the-hive-resource-monitor.service) und
  [attestierter Einstiegspunkt](../../bin/the-hive-resource-monitor)
