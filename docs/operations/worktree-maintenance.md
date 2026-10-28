# Hive-Worktree-Wartung

Dieses Verfahren zeigt zuerst eine unverbindliche, nur lesende Vorschau. Eine erste Freigabe bindet die geprüfte Vorschau an den aktuellen Code, die Protokollversion, die konfigurierte Projektliste, die Projekt- und Archivverzeichnisse sowie die erkannte Aufrufabdeckung. Der tägliche Benutzer-Timer startet ausschließlich den bereits freigegebenen Lauf. Die Freigabe ersetzt keine erneute Prüfung der Kandidaten, der Lifecycle-Evidenz oder der Prozessreferenzen.

## Vorschau und erste Freigabe

Die Vorschau wird mit folgendem Befehl erzeugt:

```sh
the-hive-mcp worktree-maintenance plan
```

Ohne Unterbefehl wird dieselbe lesende Vorschau angezeigt. Für jeden Kandidaten nennt sie den Pfad, den Lifecycle-Nachweis, die belegte Größe, die Ausschlussgründe und das Ergebnis der verfügbaren Host-Referenzprüfung. Ein ausgeschlossener oder nicht prüfbarer Kandidat bleibt geschützt.

Eine Freigabe muss den Digest aus genau der geprüften Vorschau verwenden:

```sh
the-hive-mcp worktree-maintenance approve --preview-digest sha256:<digest-aus-der-vorschau>
```

Die Freigabe speichert nur den Digest und den gebundenen Vertragsdigest im Hive-State. Sie verändert keine Projektquelle. Änderungen an Code, Protokoll, stabiler Projektkonfiguration, konfigurierten Projekt- oder Archivpfaden und Aufrufabdeckung machen die Freigabe ungültig. Eine neue Vorschau und erneute Freigabe sind dann erforderlich. Flüchtige Geräte-, Inode-, Mount- und Namespace-Identitäten gehören nicht zu dieser dauerhaften Freigabe. Der Owner prüft die aktuelle Quell- und Archividentität bei jedem Vorgang erneut und verweigert den Lauf vor einem Claim, wenn die physischen Prüfungen nicht übereinstimmen oder nicht zuverlässig möglich sind. Eine solche momentane Abweichung verbraucht die stabile Freigabe nicht.

## Schwellen und Schutzregeln

Normale Worktrees werden erst nach 30 Tagen ohne Nutzung vorgeschlagen. Worktrees mit mindestens 10 GiB zugewiesenen Blöcken können nach sieben Tagen vorgeschlagen werden. Verwaltete temporäre Verzeichnisse werden frühestens sieben Tage nach einem belegten Ende ihrer erzeugenden Runtime vorgeschlagen. Alter, Verzeichnisname, Prozessstatus oder fehlende Rückmeldung ersetzen keinen Ende-Nachweis.

Aktive oder unklare Nutzungen, fehlende oder fehlerhafte Lifecycle-Daten, Fremdeigentum, Mountgrenzen, offene Prozessreferenzen, nicht lesbare gleich-UID-Prozessdaten und veränderte Identitäten schließen eine Quelle aus. Der Lauf prüft diese Bedingungen erneut. Eine bekannte unvollständige Host-Referenzsicht wird vor einem Claim lesend erkannt und beendet den Lauf ohne Claim.

## Lauf, Archive und Wiederherstellung

Der automatische Lauf verwendet denselben serverseitigen Owner wie die manuellen Aktionen:

```sh
the-hive-mcp worktree-maintenance run
```

Einzelne Archive verwenden `archive` beziehungsweise `archive-temp`; beide nehmen nur Projekt-ID und Quellpfad entgegen. Ein freies Archivziel oder ein vom Aufrufer konstruiertes Kandidatenobjekt wird nicht akzeptiert. Der bestehende Owner enthält einen positiven Apply-Pfad für kontrollierte, belegte Temp-Producer: Er sichert die Quelle im Projektarchiv, übergibt die eigene Quelle an die gebundene Quarantäne und entfernt sie erst nach erneuter Identitäts- und Referenzprüfung. Dieser Pfad ist durch eigene Fixtures geprüft. Der produktive Lauf bleibt dennoch gesperrt, solange Native-Aufrufabdeckung, vollständige Host-Referenzsicht und die übrigen unabhängigen Live-Gates nicht belegt sind. Die Erstfreigabe setzt diese Sicherheitsgates nicht außer Kraft. Archivieren allein entfernt keine Quelle.

Das Archiv liegt im privaten `.hive-archive`-Verzeichnis des kanonischen Projekts. Das State-Verzeichnis speichert ausschließlich Lifecycle-Journal und Freigabe. Restore ist für bereits verifizierte Archive verfügbar. Er akzeptiert eine Archiv-ID statt eines Pfades und restauriert in ein neues privates Ziel unter `.hive-restores`; ein vorhandenes Ziel wird nicht überschrieben.

```sh
the-hive-mcp worktree-maintenance restore \
  --repository-id codex-master \
  --archive-id archive-<geraete-id>-<inode>-<kennung> \
  --destination-name wiederhergestellter-worktree
```

Die CLI gibt den tatsächlich restaurierten Worktree-Pfad aus. Vor einer weiteren Nutzung muss die Wiederherstellung geprüft werden. Recovery wiederholt keine Archiv- oder Löschoperation. Für eine unvollständig entfernte oder kollidierende Worktree-Operation bleibt der Claim in `recovery_hold`; ein altes Claim-Journal erteilt keine Löschfreigabe. Ein positiver Temp-Rückweg ist davon getrennt: Nach nachgewiesenem Ende des alten Writers und Freigabe des Archiv-Locks durch alle Lockhalter sowie einem erneuten Fence kann der Owner eine bereits quarantänisierte Tempquelle nur bei freiem Originalnamen und übereinstimmender Quell-, Receipt- und Inode-Identität mit NOREPLACE zurückstellen. Er schließt diesen Rückweg als `source_restored` ab. Ist der Name belegt oder die Identität beziehungsweise Writerfreiheit unklar, bleibt der Vorgang geschützt; Recovery überschreibt nichts und startet keinen Delete-Replay.

```sh
the-hive-mcp worktree-maintenance recover \
  --repository-id codex-master \
  --source /home/teladi/the_hive/.codex-master-worktrees/<worktree-name>
```

Ein aktiver Owner, ein belegter Writer oder ein unbekannter Lockzustand führt zu einer Verweigerung. Ein erfolgreiches Ergebnis mit `recovery_hold` braucht eine gesonderte Prüfung; es ist kein Abschluss- oder Löschbeleg. Ein wiederhergestellter Temp-Vorgang kann stattdessen `source_restored` melden; dies bestätigt ausschließlich den gebundenen Rückweg und keine Archivierung oder Entfernung.

## Timer und Betrieb

`the-hive-worktree-maintenance.timer` startet einmal täglich den Benutzer-Service. Der Service ist ein gewöhnlicher Benutzerprozess. Er verwendet keine `ProtectSystem`-/`ReadWritePaths`-Filesystem-Namespace-Sandbox, deren getrennte Bind-Mount-IDs mit gespeicherten Worktree-Identitäten kollidieren könnten. Er erhält keine zusätzliche Schreibberechtigung; Unix-UID/GID-Rechte und die kanonische Server-/Lifecycle-Prüfung bestimmen die zulässigen Operationen. `PrivateTmp` ist nicht gesetzt, sodass verwaltete `/tmp`-Producer sichtbar bleiben.

Die Units wurden durch diese Arbeit weder kopiert noch installiert oder aktiviert. Prüfe zuerst mit `plan`, dass der geladene `repo_root()` und die konfigurierte Repository-Liste den erwarteten Installationsstand zeigen. Die folgenden Schritte sind erst zulässig, wenn Native-Aufrufabdeckung, die produktive Freigabe des Temp-Apply-/Entfernungspfads, Host-Referenzsicht und Service-Startpfad geschlossen und unabhängig geprüft sind. Der Temp-Apply-/Entfernungspfad ist in kontrollierten Fixtures vorhanden, aber wegen der offenen Live-Gates nicht für produktive Quellen freigegeben. Im aktuellen Stand sind diese produktiven Gates offen.

```sh
install -Dm644 systemd/user/the-hive-worktree-maintenance.service \
  "$HOME/.config/systemd/user/the-hive-worktree-maintenance.service"
install -Dm644 systemd/user/the-hive-worktree-maintenance.timer \
  "$HOME/.config/systemd/user/the-hive-worktree-maintenance.timer"
systemctl --user daemon-reload
systemctl --user enable --now the-hive-worktree-maintenance.timer
```

Nach der Installation ist zuerst die aufgelöste Unit zu prüfen. Verwende `systemd-analyze --user verify` mit dem tatsächlichen Service- und Timerpfad. Prüfe zusätzlich `systemctl --user cat the-hive-worktree-maintenance.service` und bestätige den ExecStart-Pfad gegen die installierte Runtime. Die Unit enthält keine schreibenden Mountpfadlisten; sie behauptet deshalb keine Filesystem-Namespace-Isolation.

Zum Pausieren oder Zurücknehmen der Aktivierung:

```sh
systemctl --user disable --now the-hive-worktree-maintenance.timer
systemctl --user stop the-hive-worktree-maintenance.service
rm "$HOME/.config/systemd/user/the-hive-worktree-maintenance.timer" \
  "$HOME/.config/systemd/user/the-hive-worktree-maintenance.service"
systemctl --user daemon-reload
```

Das Zurücknehmen der Units löscht weder Archive noch Hive-State. Prüfe vor einer späteren erneuten Aktivierung den aktuellen Plan und die Freigabe erneut.

Der Timer ist kein Nachweis erfolgreicher Wartung. Ein verweigerter Lauf muss anhand seines Grundes untersucht werden. Ein abgebrochener oder unklarer Claim darf nicht durch Ablaufzeit, PID-Verlust oder einen manuellen Statuswert als abgeschlossen markiert werden.
