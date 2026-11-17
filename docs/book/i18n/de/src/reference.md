# Referenz

## Befehle

- `amivuln [OPTIONS] TARGET...` ist eine Kurzform für `amivuln check`.
- `amivuln check [TARGET...] [--all]`
- `amivuln cve CVE-ID...`: Ist dieser Host betroffen? Exit 1, wenn ja.
- `amivuln pending`: die Updates, die das meiste Risiko schließen, nach Rang sortiert.
- `amivuln services`: das Paket hinter jedem laufenden systemd-Dienst prüfen.
- `amivuln restart`: Prozesse, die noch Dateien nutzen, die ein Update ersetzt hat. Exit 1, wenn ein Neustart nötig ist.
- `amivuln config show | init [--path FILE] | validate`
- `amivuln cache info | clear`
- `amivuln completions bash|zsh|fish|elvish|powershell`
- `amivuln db build|pull|verify|info`: die Offline-Advisory-Datenbank (siehe [Benutzerhandbuch](guide.md))
- `amivuln tui`: eine Vollbildansicht mit Filtern (Build mit `--features tui`)
- `amivuln mcp`: ein schreibgeschützter Model-Context-Protocol-Server über stdio (siehe [Benutzerhandbuch](guide.md))
- `amivuln version [--json]`

## Optionen

- `-f, --format`: `summary`, `detail`, `json`, `sarif`, `markdown`, `csv`, `prometheus`, `cyclonedx` oder `openvex`
- `[network] retries = 2`: Wiederholungsversuche pro fehlschlagendem Aufruf; `cooldown = "30s"`: Pause des Circuit Breakers; `min_interval`: optionaler Abstand pro Host
- `--output FILE`: das Ergebnis in FILE statt nach stdout schreiben; die Datei wird atomar über ein Rename ersetzt
- `--fail-on`: `none`, `low`, `medium`, `high`, `critical` oder `kev`
- `--fail-on-epss SCORE`: Exit 1, wenn ein betroffener Fund diesen EPSS-Wert erreicht
- `--strict`: nicht verifizierte Funde zählen für `--fail-on`
- `--offline`, `--no-cache`: Verhalten bei Netzwerk und Cache
- `--config FILE`: nur diese Konfigurationsdatei verwenden
- `--color auto|always|never`: `NO_COLOR` wird beachtet
- `--distro fedora:NN|arch|debian:NN|ubuntu:NN.NN|alpine:N.NN|opensuse:NN.N|opensuse:tumbleweed|gentoo|rhel:N|rocky:N|alma:N`: den Host als diese Distribution behandeln
- `--baseline FILE`: ein früherer `-f json`-Bericht; nur Funde, die darin fehlen, verletzen `--fail-on`
- `--pid PID`: die ausführbare Datei eines laufenden Prozesses prüfen (wiederholbar); ein Prozess, der beendet, nicht lesbar ist oder dessen ausführbare Datei auf der Platte ersetzt wurde, wird als nicht aufgelöst gemeldet
- `--sbom FILE`: die OS-Pakete eines CycloneDX-JSON-SBOM prüfen (rpm-, deb-, apk- und alpm-purls); andere Komponenten werden als nicht aufgelöst aufgeführt, ein Eintrag pro purl-Typ
- `--vex FILE`: ein `OpenVEX`-Dokument; eine `not_affected`-Aussage überschreibt das Urteil und zeigt Autor und Begründung
- `--kernel`: auch den laufenden Kernel prüfen, was sonst installiert ist (siehe [Benutzerhandbuch](guide.md))
- `--explain`: unter jedem Fund der detail-Ausgabe in einfachen Worten sagen, warum er gemeldet wird (Vorlagen über die eigenen Daten des Laufs; kein Modell, nichts wird gesendet)
- `--mitigations`: auch die Mitigation nachschlagen, die Red Hat für jede betroffene CVE veröffentlicht (sendet die CVE-IDs an access.redhat.com)
- `--flatpak`: auch die Komponenten der installierten Flatpak-Runtimes prüfen (siehe [Benutzerhandbuch](guide.md) für Kosten und Grenzen)
- `--container ID`: die Pakete eines podman- oder docker-Containers prüfen (wiederholbar); Images von Alpine, Debian, Ubuntu, Fedora, openSUSE, Gentoo, Rocky, AlmaLinux und Red Hat (UBI) werden aus einem exportierten Root-Dateisystem gelesen, und nichts wird darin ausgeführt
- `--packages-from FILE`: die in FILE aufgeführten Pakete prüfen (ein `name@version` pro Zeile) statt der installierten
- `ignore_file` (Konfiguration): akzeptierte Funde; abgelaufene Einträge sind Fehler
- `-q, --quiet`: nur Fehler

`AMIVULN_FORMAT`, `AMIVULN_FAIL_ON`, `AMIVULN_OFFLINE`, `AMIVULN_CONFIG` und
`AMIVULN_COLOR` setzen die entsprechenden Optionen.

## Exit-Codes

- 0: abgeschlossen, nichts auf oder über `--fail-on`
- 1: abgeschlossen, Funde auf oder über `--fail-on`
- 2: unvollständig: eine erforderliche Quelle war nicht verfügbar
- 3: ein Ziel konnte nicht aufgelöst werden
- 64: Fehler bei Aufruf oder Konfiguration
- 70: interner Fehler

Treffen mehrere zu, gilt die Rangfolge 70, 64, 2, 3, 1, 0.

## JSON-Ausgabe (Schema-Version 1)

```json
{
  "schema_version": 1,
  "tool": {"name": "amivuln", "version": "0.1.0"},
  "generated_at": "2026-11-08T12:00:00Z",
  "host": {"os_id": "fedora", "os_version": "44", "arch": "x86_64"},
  "complete": true,
  "sources": [{"id": "fedora-updateinfo", "status": "ok", "age_s": 0, "required": true}],
  "targets": [{
    "input": "nginx",
    "package": {"name": "nginx", "version": "1:1.26.2-1.fc44", "arch": "x86_64",
                "ecosystem": "fedora", "purl": "pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64&epoch=1",
                "provenance": "package_db"},
    "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0, "epss_max": 0.02, "unverified": 0},
    "findings": [{"id": "CVE-2026-0001", "severity": "high",
                  "distro_status": {"state": "affected", "fixed_in": "1:1.26.3-1.fc44"},
                  "kev": null, "epss": {"score": 0.02, "percentile": 0.6, "date": "2026-11-07"}}],
    "unverified": []
  }],
  "unresolved": []
}
```

Das JSON-Schema ist unter [JSON-Schema](json-schema.md) veröffentlicht und wird in der CI gegen die echte Ausgabe geprüft. Funde und nicht verifizierte Funde sind getrennte Arrays. Der Host-Block
enthält nie einen Hostnamen, eine Adresse oder einen Benutzer. Das Hinzufügen optionaler Felder ändert
`schema_version` nicht; das Entfernen oder Umtypisieren eines Feldes schon.

## Konfigurationsdatei

```toml
schema_version = 1
[general]
offline = false
cache_ttl = "6h"
stale_max_age = "72h"
timeout = "10s"
exec_version_probe = false
[output]
format = "summary"
color = "auto"
[policy]
fail_on = "none"
fail_on_incomplete = true
strict = false
[sources.distro]
enabled = true
required = true
# url = "https://mirror.example/fedora/linux/updates"
[sources.kev]
enabled = true
[sources.epss]
enabled = true
```
