---
priority: hoch
---

# Installation des Resource-Scope-Gates durch den Root-Consumer

## Zweck und Grenze

Das Resource-Scope-Gate wird unter `/usr/libexec/the-hive-resource-scope-gate` ausgeführt. Die Installation dorthin erfordert Root-Rechte. Der eigenständige Consumer `scripts/install-the-hive-resource-scope-gate` ist dafür vorgesehen. Er verwendet ausschließlich die Python-Standardbibliothek und importiert weder das Hive-Paket noch Module aus dem Home-Verzeichnis der Benutzerin.

Der bisherige Befehl `the-hive-mcp install-resource-scope-gate` ist absichtlich geschlossen. Er meldet `resource_scope_gate_root_consumer_required` und verändert keine Datei. Er darf nicht als erfolgreicher Installationsnachweis verwendet werden. Das neue Skript ist der einzige vorgesehene Publisher. Es akzeptiert nur `--uid`, `--generation` und `--manifest-sha256`; Zielpfad und Gate-Dateiname sind fest im Skript vorgegeben.

Diese Anleitung beschreibt den geprüften Installationsvertrag. Sie ist keine Freigabe für eine Root-Ausführung. Für eine spätere Ausführung müssen die Platzhalterwerte vorab aus einem eingefrorenen, unabhängig geprüften Releasepaket übernommen werden. Die tatsächliche Root-gegen-User-Release-Attestierung und ein vollständiger G5-Lauf bleiben gesonderte offene Gates.

## Eingaben, die vorab unabhängig feststehen müssen

Die Freigabeperson muss die folgenden Werte aus einem unveränderlichen, unabhängig geprüften Paket beziehen. Sie darf Generation oder Digest nicht erst aus dem aktuellen Pointer des installierenden Benutzers ableiten.

| Wert                       | Quelle und Prüfung                                                    |
| -------------------------- | --------------------------------------------------------------------- |
| `APPROVED_SOURCE_COMMIT`   | Vollständiger Commit des geprüften Hive-Sourcepakets.                 |
| `APPROVED_CONSUMER_SHA256` | SHA-256 des geprüften `scripts/install-the-hive-resource-scope-gate`. |
| `APPROVED_GATE_SHA256`     | SHA-256 des geprüften `bin/the-hive-resource-scope-gate`.             |
| `APPROVED_UID`             | Numerische UID der Benutzerin, deren Release geprüft wurde.           |
| `APPROVED_GENERATION`      | Generation aus dem unabhängig geprüften Releasepaket.                 |
| `APPROVED_MANIFEST_SHA256` | SHA-256 der zugehörigen Runtime-Manifestdatei aus demselben Paket.    |

Die Werte in Großbuchstaben sind Dokumentationsnamen und keine ausführbaren Shellvariablen. Vor einem Einsatz müssen sie durch konkrete Werte aus dem geprüften Paket ersetzt und von der Operatorin gegengeprüft werden. Solange diese Pin-Werte fehlen, darf die Installation nicht ausgeführt werden.

## Vorbereitete User-Releasequelle

Die Root-Installation darf erst auf eine neu erzeugte, benutzereigene Generation zeigen, die aus dem unabhängig geprüften und sauberen Source-Commit erstellt wurde. Vorher müssen der tatsächliche Release-Owner, sein privater Build- und Canary-Ablauf sowie die erzeugte Generation, der aktuelle Pointer, das Manifest und der Gate-Member geprüft sein. Ein bereits installiertes Live-Release ist keine angenommene Quelle für das neue Gate. Ein vorhandener Pointer allein belegt weder den erwarteten Commit noch die geprüfte Herkunft.

Der hier beschriebene Slice hat noch keine solche Generation veröffentlicht oder auf einen Live-Pointer umgeschaltet. Es wurden weder Runtime-Units noch Resource-Monitor-Services installiert oder aktiviert. Für einen späteren G5-Nachweis ist ein eigener kontrollierter 0.161-Testscope mit den normalen Resource-/G5-Ownern erforderlich. Persönliche Daemons oder fremde Units dürfen dafür nicht herangezogen werden. Eine fehlende Root-Konsole oder eine nicht belegte Herkunft der Generation bleibt ein technisches Gate und wird nicht durch einen CLI-Erfolg ersetzt.

## Vom Consumer geprüfte Releasequelle

Der Consumer löst das Home-Verzeichnis anhand der angegebenen UID auf und prüft das festgelegte Release unter:

```text
<home>/.local/lib/the-hive-runtime
```

Er nimmt eine gemeinsame Lesesperre auf `.the-hive-release-publish.lock`, prüft den aktuellen Release-Pointer und bindet diesen an die unabhängig übergebenen Werte für Generation und Manifest-Digest. Anschließend liest er die Manifestdatei und genau den Eintrag `bin/the-hive-resource-scope-gate`. Verzeichnis-, Datei-, Eigentümer-, Modus-, Linkzahl-, Größen- und Inhaltsprüfungen erfolgen über gepinnte Dateideskriptoren. Vor der Veröffentlichung werden Pointer, Manifest, Gate-Datei und Verzeichnisidentitäten erneut geprüft.

Die Veröffentlichung zielt ausschließlich auf `/usr/libexec/the-hive-resource-scope-gate`. Ein byte- und metadatenidentisches, root-eigenes Ziel ist idempotent. Ein fehlendes Ziel wird über eine eindeutig eigene, root-eigene und für gewöhnliche Benutzer schreibgeschützte Stagingdatei sowie atomare No-Replace-Umbenennung veröffentlicht. Die Stage liegt im Zielverzeichnis und ist daher lesbar; die Gate-Bytes sind nicht als Geheimnis behandelt. Ein unbekanntes, abweichendes, verlinktes oder zwischenzeitlich entstandenes Ziel wird nicht überschrieben. Eine unvollständige oder fremde Stagingdatei führt zu einem geschützten Fehlerzustand; sie wird nicht automatisch entfernt.

## Geprüfter Ablauf für eine spätere Root-Ausführung

Der folgende Ablauf ist eine Vorlage. Er wurde in dieser Arbeit nicht mit Root-Rechten ausgeführt. Die konkreten Pins müssen zuerst aus dem eingefrorenen Paket stammen.

1. Die Operatorin prüft, dass das Paket dem unabhängig geprüften Source-Commit entspricht und dass Consumer- und Gate-Hash mit den separat dokumentierten Pins übereinstimmen.
2. Sie kopiert ausschließlich das geprüfte Consumer-Skript in eine root-eigene Stagingdatei innerhalb des zuvor neu erzeugten Verzeichnisses mit Modus `0700`.
3. Sie prüft an der Stagingdatei Eigentümer, Modus, Linkzahl und SHA-256. Die Datei muss root-eigen, regulär, mit Modus `0755` und genau einem Link sein.
4. Sie führt das geprüfte Staging-Skript mit leerer Python-Umgebung und isoliertem Python-Modus aus. Es werden ausschließlich UID, Generation und Manifest-Digest übergeben.
5. Sie prüft das JSON-Ergebnis und anschließend Eigentümer, Modus, Linkzahl und Hash des festen Zieles. Ein Fehler oder ein unklarer Stagingzustand wird als nicht installiert behandelt.

Beispielvorlage, die vor Einsatz mit konkreten unabhängig geprüften Werten vervollständigt werden muss:

```sh
set -eu
stage_dir=$(/usr/bin/mktemp -d -p /run the-hive-gate-install.XXXXXXXXXX)
test "$(/usr/bin/stat -c '%u:%a' "$stage_dir")" = "0:700"
/usr/bin/install -o root -g root -m 0755 \
  scripts/install-the-hive-resource-scope-gate \
  "$stage_dir/install-the-hive-resource-scope-gate"
/usr/bin/stat -c '%u %a %h %n' \
  "$stage_dir/install-the-hive-resource-scope-gate"
test "$(/usr/bin/stat -c '%u:%a:%h' "$stage_dir/install-the-hive-resource-scope-gate")" = "0:755:1"
actual_consumer_sha=$(/usr/bin/sha256sum "$stage_dir/install-the-hive-resource-scope-gate" | /usr/bin/cut -d ' ' -f 1)
test "$actual_consumer_sha" = "APPROVED_CONSUMER_SHA256"
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
  /usr/bin/python3 -I -B \
  "$stage_dir/install-the-hive-resource-scope-gate" \
  --uid APPROVED_UID \
  --generation APPROVED_GENERATION \
  --manifest-sha256 APPROVED_MANIFEST_SHA256
test "$(/usr/bin/stat -c '%u:%a:%h' /usr/libexec/the-hive-resource-scope-gate)" = "0:755:1"
actual_gate_sha=$(/usr/bin/sha256sum /usr/libexec/the-hive-resource-scope-gate | /usr/bin/cut -d ' ' -f 1)
test "$actual_gate_sha" = "APPROVED_GATE_SHA256"
```

Die Vorlage ist nicht ausführbar, solange die benannten Platzhalter nicht ersetzt und mit dem unabhängigen Paketbeleg verglichen wurden. Das Stagingverzeichnis wird pro Lauf neu unter dem geprüften Root-Verzeichnis `/run` erzeugt; ein vorhandener Pfad wird nicht übernommen. Die Hash- und Metadatenprüfungen müssen vor dem Start des Consumers erfolgreich sein. Der Gate-Hash wird zusätzlich nach erfolgreicher Veröffentlichung mit dem unabhängigen Paketpin verglichen. Es darf keine zusätzliche Option für Zielpfad, Quelle oder Überschreiben ergänzt werden.

## Fehler und Wiederaufnahme

Bei einem Fehler ändert der Consumer kein unbekanntes Ziel. Ein bereits vorhandenes bytegleiches, korrekt geschütztes Ziel kann als `already_installed` bestätigt werden. Eine fremde oder nur teilweise passende Datei wird abgelehnt und bleibt unverändert. Eine vollständige, eigene Stagingdatei mit dem erwarteten Digest kann nach einem Abbruch wiederverwendet werden. Eine abweichende Stagingdatei muss manuell untersucht werden; der Consumer entfernt sie nicht.

Die User-CLI ist kein Wiederaufnahmeweg. Sie kann weder den Root-Publisher aufrufen noch dessen Ergebnis behaupten. Diese Anleitung setzt keine Units, Timer oder Services in Betrieb und verändert keine vorhandene Resource-Monitor-Installation.

## Noch nicht belegte Grenzen

Der Consumer ist lokal getestet, jedoch nicht mit Root-Rechten auf dem Host ausgeführt worden. Der Übergang zwischen root-eigenem Installer und user-eigener attestierter Releasegeneration muss noch durch den tatsächlichen autorisierten Installationspfad nachgewiesen werden. Ebenso steht ein echter G5-Start mit gebundener Scope-Identität und belegter Scope-Leere nach Ende noch aus. Bis diese Prüfungen abgeschlossen sind, darf aus einem erfolgreichen lokalen Test keine produktive Gate- oder G5-Freigabe abgeleitet werden.
