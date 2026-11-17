# Architektur

amivuln ist ein Cargo-Workspace. Das Binary `amivuln` orchestriert nur; die
Domänenregeln führen keine I/O aus.

## Pipeline

1. **Ziel.** Wonach der Benutzer gefragt hat: ein Paketname, ein Dateipfad,
   eine `.service`-Unit, `name@version` oder eine purl (`amivuln-resolve`).
2. **Identität.** Das installierte Paket, gelesen aus dem Paketmanager
   (`rpm`, `pacman`) über einen Subprozess-Runner mit Allowlist und
   Begrenzungen, aus der exportierten Paketdatenbank eines Containers (dpkg,
   apk oder rpm), aus einer Liste oder einer SBOM oder aus den eigenen
   Metadaten einer Datei (Paket-Note, Go-Build-Informationen,
   `cargo-auditable`).
3. **Distributionsdaten.** Die eigenen Advisory-Daten der Distribution,
   abgerufen über einen cache-fähigen HTTP-Client (`amivuln-sources`,
   `amivuln-cache`).
4. **Abgleich.** Der Status der Distribution entscheidet, nie ein
   Upstream-Versionsbereich. `Fixed(v)` mit einer installierten Version ab `v`
   gilt als gepatcht; eine ältere ist betroffen und nennt die Version, die den
   Fehler behebt (`amivuln-core`).
5. **Anreicherung.** CISA KEV und FIRST EPSS.
6. **Richtlinie.** `--fail-on`, `--fail-on-epss`, `--strict` und die
   Rangfolge der Exit-Codes 70, 64, 2, 3, 1, 0.
7. **Bericht.** `summary`, `detail`, JSON, SARIF, Markdown, CSV und Prometheus (`amivuln-report`).

## Crates

- `amivuln`: Kommandozeile, Konfiguration und Orchestrierung.
- `amivuln-core`: Domänentypen, Abgleichsregeln, Richtlinie, Exit-Codes und
  die Traits für die Außenwelt.
- `amivuln-resolve`: Auflösung des Ziels und der System-Prozess-Runner.
- `amivuln-version`: Versionsvergleich für RPM, pacman, Debian, apk und
  Semantic Versioning, verifiziert gegen `rpm`, `vercmp`, `dpkg` und
  `apk version -t`.
- `amivuln-sandbox`: die Landlock- und seccomp-Sandbox der optionalen
  Versionsprobe, das einzige Crate mit `unsafe`-Code.
- `amivuln-sources`: Parser für den Arch Security Tracker, Fedora
  `updateinfo`, OSV, NVD, CISA KEV und FIRST EPSS sowie der begrenzte
  HTTP-Client.
- `amivuln-cache`: SQLite-HTTP-Cache mit ETag-Revalidierung und der
  Einstufung frisch/veraltet/abgelaufen (fresh/stale/expired).
- `amivuln-report`: Ausgabeformatierer.

Alle Crates sind auf crates.io veröffentlicht, weil das Binary von ihnen
abhängt. Die Bibliotheks-Crates teilen sich die Version des Binarys und tragen
weder bei 1.0 noch danach ein API-Stabilitätsversprechen: Der Vertrag ist der
Befehl (siehe die [Support-Richtlinie](support.md)).

## Invarianten

- Der Status der Distribution hat Vorrang vor dem Upstream-Versionsvergleich.
- Ein Fund ohne Aussage der Distribution ist *nicht verifiziert*, wird
  gesondert aufgeführt und nie als betroffen gezählt.
- Eine ausgefallene erforderliche Quelle macht das Ergebnis unvollständig
  (Exit-Code 2). Veraltete Cache-Daten innerhalb von `stale_max_age` werden
  verwendet und als `stale` gemeldet.
- Jede gelesene Datei, jede HTTP-Antwort und jede Subprozess-Ausgabe ist in
  der Größe begrenzt, jeder Subprozess hat ein Timeout und einen absoluten
  Pfad aus der Allowlist, und es ist keine Shell beteiligt.
- Text von außerhalb des Prozesses wird bereinigt, bevor er ein Terminal
  erreicht.
- In der Ausgabe und in den Anfragen gibt es kein Feld, das den Host
  identifiziert.
