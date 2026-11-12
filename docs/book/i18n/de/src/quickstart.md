# Schnellstart

```bash
amivuln nginx                          # ein installiertes Paket
amivuln /usr/sbin/nginx                # das Paket, dem eine Datei gehört
amivuln nginx.service                  # das Paket hinter einer systemd-Unit
amivuln openssl@3.5.1-1 --distro arch  # eine Version, ohne den Host zu lesen
amivuln --all                          # jedes installierte Paket
```

## Fragen zum ganzen Host

```bash
amivuln cve CVE-2024-6387      # ist ein installiertes Paket betroffen?
amivuln pending                # welche Updates das Risiko am meisten senken, riskanteste zuerst
amivuln services               # prüft das Paket hinter jedem laufenden Dienst
amivuln restart                # welche Prozesse noch von einem Update ersetzte Dateien nutzen
amivuln --packages-from list.txt   # prüft eine von einem anderen Host exportierte Paketliste
```

`cve` beendet sich mit Code 1, wenn ein Paket betroffen ist. Hat die Distribution
keinen Eintrag zur CVE, sagt amivuln das ausdrücklich: Das ist keine Aussage,
dass der Host sicher ist. `pending` fasst aus einer Quelle gebaute Unterpakete
zu einem Update zusammen und sortiert nach ausgenutzten Funden (KEV),
Schweregrad und EPSS. `restart` liest `/proc` (als root ausführen, um alle
Prozesse zu sehen; die Ausgabe nennt, wie viele nicht geprüft werden konnten)
und beendet sich mit Code 1, wenn etwas neu gestartet werden muss. `services`
listet laufende systemd-Dienste auf, die nicht aus einem Paket stammen, ohne
den Lauf scheitern zu lassen. Ein Scan des ganzen Systems gibt außerdem eine
Host-Note von A bis F aus (siehe ADR-0011 im Repository).

## Das Ergebnis lesen

Für jedes Paket erhalten Sie die Zahl der betroffenen Funde nach Schweregrad,
wie viele bekanntermaßen ausgenutzt werden (CISA KEV), den höchsten EPSS-Wert
und die Version, die sie behebt, samt dem Befehl, den Sie ausführen würden.
amivuln führt diesen Befehl nie aus.

Funde, die die Distribution nicht bestätigen kann, stehen getrennt als
*nicht verifiziert* und werden nicht zu den betroffenen gezählt.

## Einen Build scheitern lassen

```bash
amivuln --all --fail-on high           # Code 1 bei HIGH oder schlimmer
amivuln --all --fail-on kev            # Code 1 nur bei ausgenutzten CVEs
amivuln --all -f sarif > amivuln.sarif # SARIF 2.1.0 für Code Scanning
amivuln --all -f csv > amivuln.csv     # tabellenkalkulationssicher (Formelinjektion abgewehrt)
```

Exit-Codes: `0` sauber, `1` Funde auf dem Niveau von `--fail-on` oder darüber,
`2` unvollständig, `3` Ziel nicht aufgelöst, `64` Verwendungsfehler, `70`
interner Fehler. Code `2` verhindert, dass ein Ausfall der Sicherheitsdaten als
sauberer Scan durchgeht.

## Ein GitHub-Actions-Schritt

Die [amivuln-action](https://github.com/nubian-ibex/amivuln-action) lädt ein
Release herunter, prüft Attestierung und Prüfsumme und führt es dann aus.
Pinnen Sie sie auf einen vollständigen Commit-SHA:

```yaml
permissions:
  contents: read
  attestations: read
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high
```

Dieselben Schritte von Hand:

```yaml
- name: amivuln herunterladen
  run: |
    gh release download --repo nubian-ibex/amivuln --pattern 'amivuln-x86_64-unknown-linux-musl.tar.zst'
    gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
    tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
- name: Pakete prüfen
  run: ./amivuln --all --fail-on high
```

Weitere Szenarien finden Sie unter [amivuln verwenden](using.md).
