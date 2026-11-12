# amivuln verwenden

Rezepte für die Orte, an denen amivuln üblicherweise läuft. Jedes ist
vollständig genug zum Kopieren; das
[Benutzerhandbuch](https://ibexwall.com/amivuln/guide.html) erklärt die
Optionen im Detail, die
[Referenz](https://ibexwall.com/amivuln/reference.html) listet alle auf.

Zwei Dinge gelten überall. Lesen Sie `complete` und die `source`-Zeilen, bevor
Sie einem leeren Ergebnis trauen: Exit-Code `2` bedeutet, dass eine
erforderliche Quelle nicht verfügbar war, und das ist nicht dasselbe wie
sauber. Und nur Ökosystem, Paketname und Version verlassen den Rechner.

## Auf Ihrem Laptop oder Arbeitsplatzrechner

```bash
amivuln --all                      # Note und Summen für alle installierten Pakete
amivuln pending                    # welche Updates das Risiko am meisten senken, riskanteste zuerst
amivuln openssl --format detail    # ein Paket, jeder Fund mit seiner Behebung
amivuln /usr/bin/ssh               # das Paket, dem eine Datei gehört
```

`pending` ist auf einem Desktop am nützlichsten: Es fasst aus einer Quelle
gebaute Unterpakete zusammen, sortiert nach ausgenutzten Funden (KEV),
Schweregrad und EPSS und gibt den Update-Befehl aus. amivuln führt ihn nie aus.

Für eine Vollbildansicht mit Filtern kompilieren Sie mit dem Feature `tui`:

```bash
cargo install amivuln --locked --features tui
amivuln tui          # Pfeiltasten oder j/k zum Bewegen, K: nur KEV, H: nur HIGH, q: Beenden
```

## Wenn eine neue CVE in den Nachrichten ist

```bash
amivuln cve CVE-2024-6387          # Code 1, wenn ein installiertes Paket betroffen ist
amivuln cve CVE-2024-6387 CVE-2025-26465
amivuln restart                    # Prozesse, die noch von einem Update ersetzte Dateien nutzen
```

`cve` antwortet `affected`, `not affected` oder `unknown`. `unknown` bedeutet,
dass die Distribution keinen Eintrag zur CVE hat: Das ist keine Aussage, dass
der Host sicher ist. Nach der Installation des Updates listet `restart` die
Prozesse, die noch den alten Code ausführen.

## Auf einem Server, nach Zeitplan

Die Units in `contrib/systemd` scannen den Host alle sechs Stunden und
schreiben Metriken für den Textfile-Collector von node_exporter.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Importieren Sie `contrib/grafana/amivuln.json` in Grafana für das Dashboard. Für
einen einfachen Cron-Job, der das Ergebnis nur dann per Mail schickt, wenn
etwas nicht stimmt:

```cron
17 6 * * *  root  amivuln --all --fail-on high -f markdown || mail -s "amivuln: $(hostname)" ops@example.org
```

Um statt eines Dashboards eine Nachricht zu erhalten, ergänzen Sie in der
Konfiguration einen Webhook:

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"
on = "violation"
```

## In einer CI-Pipeline

GitHub Actions, mit geprüftem Release und Code Scanning:

```yaml
permissions:
  contents: read
  attestations: read
  security-events: write
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high -f sarif --output amivuln.sarif
  - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
    if: always()
    with:
      sarif_file: amivuln.sarif
```

Pinnen Sie Actions von Dritten auf einen vollständigen Commit-SHA, wie bei der
ersten. GitLab CI oder ein anderer Runner:

```yaml
amivuln:
  image: fedora:44
  script:
    - curl -sSLO https://github.com/nubian-ibex/amivuln/releases/latest/download/amivuln-x86_64-unknown-linux-musl.tar.zst
    - tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
    - ./amivuln --all --fail-on kev -f json --output amivuln.json
  artifacts:
    when: always
    paths: [amivuln.json]
```

Prüfen Sie den Download wie unter [Installation](installation.md) gezeigt, bevor
Sie sich darauf verlassen. Damit ein Pull Request nur an den Funden scheitert,
die er selbst einführt, vergleichen Sie mit einem Bericht des Hauptzweigs:

```bash
amivuln --all -f json --output baseline.json        # auf main, als Artefakt aufbewahrt
amivuln --all --baseline baseline.json --fail-on high   # im Pull Request
```

## Container und Images

Scannen Sie einen Container über ID oder Namen; die Laufzeit kann podman oder
docker sein. amivuln liest die Paketdatenbank aus einem exportierten
Dateisystem und führt darin nie etwas aus.

```bash
id=$(podman create docker.io/library/alpine:3.18.0 true)
amivuln --container "$id" --fail-on high
podman rm "$id"
```

Container mit Alpine, Debian, Ubuntu, Fedora, Rocky, AlmaLinux und Red Hat (UBI)
werden gegen ihr eigenes Release bewertet. Ein Alpine-edge- oder Alpha-Image hat
keine Advisory-Daten und wird abgelehnt, statt als sauber gemeldet zu werden.
Mit mehreren `--container`-Optionen prüfen Sie einen ganzen Stack in einem
Bericht.

## Viele Hosts, oder ein Host, auf dem Sie nichts installieren können

Exportieren Sie eine Liste vom anderen Host und prüfen Sie sie dort, wo amivuln
läuft. Ein `name@version` pro Zeile; `--distro` gibt an, zu welchem Release die
Liste gehört.

```bash
# Fedora, RHEL, Rocky, AlmaLinux (auf dem Zielhost)
rpm -qa --qf '%{NAME}@%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n' > host.txt
# Debian und Ubuntu: Advisories verwenden den Namen des Quellpakets
dpkg-query -W -f '${source:Package}@${Version}\n' > host.txt
# Alpine: Advisories verwenden das Ursprungspaket
awk -F: '/^P:/{p=$2} /^V:/{v=$2} /^o:/{o=$2} /^$/{print (o?o:p)"@"v; p="";v="";o=""}' \
  /lib/apk/db/installed > host.txt

amivuln --packages-from host.txt --distro debian:12 --fail-on high
```

Für eine Komponentenliste aus einem Build zeigen Sie auf ein CycloneDX-SBOM:

```bash
amivuln --sbom product.cdx.json --distro debian:12
```

## Kein Internet auf dem Host

Bauen Sie die Advisory-Datenbank dort, wo es ein Netz gibt, bringen Sie eine
einzige Datei hinüber und antworten Sie offline daraus.

```bash
amivuln --all -f json > /dev/null                 # den Cache einmal aufwärmen
amivuln db build --archive db.tar.zst
# db.tar.zst auf den isolierten Host kopieren, dann:
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst
amivuln --all --offline --fail-on high
```

Ergebnisse aus der Datenbank werden als `stale` mit ihrem Alter gemeldet. Das
Projekt veröffentlicht eine signierte Datenbank pro Distributionsfamilie; siehe
das Handbuch.

## Hinter einem Proxy oder einer Firmen-CA

```toml
[network]
proxy = "http://proxy.corp.example:3128"
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
```

Oder richten Sie `sources.<name>.url` auf einen internen Mirror. Siehe das
Handbuch.

## Aus Skripten und Dashboards

Der JSON-Bericht ist ein versionierter Vertrag, `jq` genügt also:

```bash
amivuln --all -f json | jq -r '.targets[] | select(.summary.kev > 0) | .package.name'
amivuln --all -f json | jq '[.targets[].findings[]] | group_by(.severity) | map({(.[0].severity): length}) | add'
amivuln --all -f csv > findings.csv        # tabellenkalkulationssicher
amivuln --all -f prometheus --output /var/lib/node_exporter/textfile_collector/amivuln.prom
```

## Aus einem KI-Assistenten

`amivuln mcp` ist ein schreibgeschützter Model-Context-Protocol-Server.
Registrieren Sie ihn einmal:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

Der Assistent kann dann Pakete prüfen, fragen, ob eine CVE den Host betrifft,
und ausstehende Updates auflisten. Er hat keine Shell, nimmt keine Dateipfade
entgegen und kann keine Optionen übergeben.

## Dateien, die keinem Paket gehören

Ein nach `/opt` kopiertes Binary, ein Go-Programm oder ein Rust-Programm aus
einem Build:

```bash
amivuln /opt/tool/bin/server          # Hinweis, Go-Build-Info oder cargo-auditable-Daten
```

Deklariert die Datei nichts, sucht amivuln nach den Versionsbannern einer
kurzen Liste von C-Produkten und markiert das Ergebnis als wenig verlässlich.
Mit `exec_version_probe = true` unter `[general]` führt es zusätzlich
`--version` auf der Datei in einer Landlock- und seccomp-Sandbox aus; das ist
standardmäßig aus.
