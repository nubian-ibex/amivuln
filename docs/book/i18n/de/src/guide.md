# Benutzerhandbuch

## Pakete prüfen

```bash
amivuln nginx                 # installiertes Paket nach Name
amivuln /usr/sbin/nginx       # das Paket, dem diese Datei gehört
amivuln openssl@3.5.1-1       # eine bestimmte Version, ohne den Host zu lesen
amivuln pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64   # eine Package-URL
amivuln --all                 # jedes installierte Paket
```

`--file PATH`, `--package NAME[@VERSION]` und `--purl PURL` sind explizite
Formen derselben Ziele und können wiederholt werden. Ist ein Name mehrdeutig
(zum Beispiel sind mehrere Kernel-Versionen installiert), bricht amivuln mit
Exit-Code 3 ab und sagt Ihnen, welchen Selektor Sie verwenden müssen. Es
rät nie.

## Das Ergebnis lesen

Die Zusammenfassung gibt pro Paket die Anzahl der betroffenen Funde nach
Schweregrad aus, wie viele davon im CISA-KEV-Katalog stehen, den höchsten
EPSS-Wert und die behobene Version mit dem Befehl, den Sie zum Einspielen
ausführen würden. amivuln führt diesen Befehl nie aus.

Funde, die die Distribution nicht bestätigen konnte, werden getrennt als
*unverified* aufgeführt und nicht mit den betroffenen gezählt. `--strict`
lässt sie für `--fail-on` zählen.

Die letzten Zeilen listen jede befragte Quelle auf, ihren Status
(`ok`, `stale`, `failed`, `skipped`), ihr Alter und ob das Ergebnis
vollständig ist. Fällt eine erforderliche Quelle aus, ist das Ergebnis
**unvollständig**: Die Ausgabe sagt das deutlich, und der Exit-Code ist 2,
sodass ein Ausfall nie wie ein sauberer Scan aussehen kann.

## Einsatz in der CI

```bash
amivuln --all --fail-on high           # den Job bei HIGH oder schlimmer scheitern lassen
amivuln --all --fail-on kev            # nur bei aktiv ausgenutzten CVEs scheitern
amivuln --all --fail-on-epss 0.5       # bei hoher Ausnutzungswahrscheinlichkeit scheitern
amivuln --all -f json > amivuln.json   # eine maschinenlesbare Aufzeichnung behalten
```

Um eine Version für eine andere Distribution zu prüfen, zum Beispiel ein
Fedora-Paket auf einem Debian-basierten Runner, übergeben Sie
`--distro fedora:44` oder `--distro arch` zusammen mit `name@version`. Nur
Ökosystem, Paketname und Version werden über das Netzwerk gesendet.

## Offline und Caching

Antworten werden in `$XDG_CACHE_HOME/amivuln/cache.sqlite` zwischengespeichert
(Standard `~/.cache/amivuln`). Eine Antwort, die jünger als `cache_ttl` (6 h)
ist, wird ohne Netzwerkanfrage verwendet; fällt das Netzwerk aus, wird eine bis
zu `stale_max_age` (72 h) alte verwendet und als `stale` gemeldet. `--offline`
berührt nie das Netzwerk und scheitert geschlossen (Exit 2), wenn der Cache
nichts Brauchbares enthält. `amivuln cache info` und `amivuln cache clear`
verwalten den Cache; `--no-cache` überspringt den Platten-Cache.

## Konfiguration

`amivuln config init` schreibt eine kommentierte Standarddatei; `amivuln config
show` gibt die wirksame Konfiguration aus und `amivuln config validate` prüft
sie. Unbekannte Schlüssel werden abgelehnt, damit Tippfehler nicht unbemerkt
durchgehen.

## Sprache

Der Text, den ein Mensch liest (die Ausgabe von summary und detail, `pending`,
`cve`, `restart` sowie die üblichen Fehler und Warnungen), folgt der Locale:
der erste gesetzte Wert aus `LC_ALL`, `LC_MESSAGES` und `LANG`, wie bei jedem
Kommandozeilenwerkzeug. Es gibt Englisch und brasilianisches Portugiesisch
(`pt`); alles andere, einschließlich `C`, ist Englisch. Für einen Lauf:
`LC_ALL=pt_BR.UTF-8 amivuln --all`.

Die Ausgaben in JSON, SARIF, CSV, Markdown, Prometheus, CycloneDX und OpenVEX
bleiben unabhängig von der Locale auf Englisch, weil andere Programme sie
lesen, ebenso der `--help`-Text, die Konfigurationsfehler und die Meldungen der
Bibliotheken, aus denen das Werkzeug gebaut ist. Schweregradnamen, `KEV` und
`EPSS` werden nicht übersetzt. Die Übersetzung wurde vom Assistenten des
Projekts geschrieben und nicht von einer Muttersprachlerin oder einem
Muttersprachler geprüft; eine Korrektur ist ein Pull Request auf eine
Textdatei (siehe CONTRIBUTING).

## Der laufende Kernel

Auf den meisten Hosts sind mehrere Kernel nebeneinander installiert, und einer
läuft, daher scheitert `amivuln kernel-core` als mehrdeutig. `amivuln --kernel`
prüft das Paket, dem das Image des laufenden Kernels gehört (das Release in
`/proc/sys/kernel/osrelease`), unabhängig davon, was sonst installiert ist:

```text
$ amivuln --kernel
kernel-core 7.2.15-200.fc44 (Fedora 44)  <- --kernel 7.2.15-200.fc44.x86_64
  CRITICAL 0   HIGH 0   MEDIUM 1   LOW 0   KEV 0
  Fixed in: 7.3.3-200.fc44  (dnf upgrade kernel-core)
```

Er wird wie jedes Paket anhand der Daten der Distribution beurteilt: Eine
Upstream-Version wird nie gegen die CVE-Einträge des Kernels selbst abgeglichen,
weil ein Distributionskernel Behebungen enthält, die die Versionsnummer nicht
zeigt. `--all` beurteilt weiterhin jeden installierten Kernel. Live-Patches
(kpatch, livepatch) kennt amivuln nicht: Es meldet, was die Paketversion sagt.
Siehe ADR-0015.

## Einen Fund erklären

`amivuln --explain -f detail` fügt unter jedem Fund die Sätze hinzu, die sagen,
warum er gemeldet wird:

```text
CVE-2026-111253  UNKNOWN  fix: 5.4.7.0-1.fc44  EPSS 0.00
      why: dnf5 5.4.6.0-1.fc44 is older than 5.4.7.0-1.fc44, the build that fixes this CVE in the distribution's data. Installing 5.4.7.0-1.fc44 or later closes it.
      why: FIRST EPSS puts the chance it is exploited in the next 30 days at 0%, above 3% of scored CVEs.
```

Die Option ist standardmäßig aus, wirkt nur auf die detail-Ausgabe (die
maschinenlesbaren Formate sind mit und ohne sie identisch) und folgt der
Sprache der Locale.

Kein Sprachmodell schreibt sie. Jeder Satz ist eine Vorlage, gefüllt aus einem
Feld, das der Lauf bereits hat (die installierte Version, die behobene
Version, der Zustand, den die Daten der Distribution lieferten, wie das Paket
identifiziert wurde, CISA KEV, EPSS, eine Mitigation des Herstellers). Derselbe
Fund ergibt also immer denselben Text, und jeder Satz lässt sich auf seine
Quelle zurückführen. Nichts wird irgendwohin gesendet. Was sie nicht leistet:
Sie beurteilt nicht, ob der verwundbare Code auf diesem Host erreichbar ist,
und sie fasst die CVE nicht zusammen (die Beschreibung wird nicht gespeichert).
Ein Treffer über ein Versionsbanner und ein in der Datei eingebettetes Paket
sagen das, weil sie schwächere Belege sind.

## Mitigations

`amivuln --mitigations` zeigt zusätzlich für jede CVE, die den Host noch
betrifft, was laut Red Hat getan werden kann, solange die Behebung nicht
installiert ist: ein Modul deaktivieren, eine Einstellung ändern, ein Skript
ausführen. Es ist Red Hats eigener Text, gelesen aus seinen öffentlichen
Sicherheitsdaten (`access.redhat.com/hydra/rest/securitydata/cve/<id>.json`),
und wird als solcher gezeigt:

```text
CVE-2024-6387  HIGH  fix: 1:9.6p1-3.fc40.3
      mitigation (Red Hat, not checked on this host): ... set LoginGraceTime to 0 ...
```

Sie ist **standardmäßig aus**, weil sie die ID jeder offenen CVE an
`access.redhat.com` sendet; `--mitigations` schaltet sie für einen Lauf ein,
`[sources.mitigations] enabled = true` für jeden Lauf. Nur `url` in dieser
Tabelle zu nennen schaltet sie nicht ein. Antworten werden eine Woche
aufbewahrt.

- Der Text ist für Red Hats eigene Produkte geschrieben. amivuln prüft nicht,
  ob er auf diesen Host zutrifft oder ob die Einstellung wirksam ist, und die
  Zeile sagt das.
- Red Hat füllt das Feld bei den meisten CVEs, um zu sagen, dass es nichts zu
  tun gibt („Mitigation for this issue is either not available or ...
  criteria“). Das ist das Fehlen einer Mitigation und wird weggelassen: In
  einem Debian-Container hatten 30 von 94 CVEs eine echte.
- Sie erscheint als `mitigation`-Objekt eines Fundes im JSON (nur wenn
  vorhanden), als `workaround` im CycloneDX-Dokument und in der
  detail-Ausgabe.
- Ein fehlgeschlagener Abruf wird in der Quelle `redhat-cve` genannt (und mit
  `required = true` ist das Ergebnis unvollständig); er wird nie als „es gibt
  keine Mitigation“ gelesen. Pro Lauf werden höchstens 400 CVEs abgefragt.

## Flatpak-Runtimes

`amivuln --flatpak` prüft zusätzlich die Komponenten der installierten
Flatpak-Runtimes (die Systeminstallation und die des Benutzers;
`FLATPAK_SYSTEM_DIR` und `FLATPAK_USER_DIR` werden beachtet). Es wird nichts
ausgeführt: Das `manifest.json` jeder Runtime wird gelesen. Die auf
freedesktop-sdk aufbauenden Runtimes (Platform, Sdk, GNOME, KDE) listen jede
Komponente mit ihrer Upstream-Version auf, dazu einen `x-cpe`-Block mit dem
NVD-Produktnamen, den CVEs, die der Build bereits gepatcht hat (`patches`), und
denen, die laut ihren Maintainern nicht zutreffen (`ignored`).

Für diese Komponenten gibt es keinen Behebungsstatus einer Distribution. Die
CVEs stammen daher aus der NVD, abgefragt für die Upstream-Version jeder
Komponente, und die Angaben des Builders entscheiden den Rest so, wie es die
Daten einer Distribution tun: Eine gepatchte CVE ist erledigt und eine
ignorierte ist „not affected“, keine von beiden ist ein Fund. Was übrig
bleibt, nennt keine behobene Version, weil die Behebung eine neuere Runtime ist
(`flatpak update`). Eine Komponente heißt `runtime/branch/component`.

Wissen Sie, was das nicht aussagt:

- Eine CVE, die der Build gepatcht, aber nicht in `patches` aufgeführt hat,
  erscheint als offen. Das zlib in der Runtime 25.08 ist für CVE-2026-22184
  aufgeführt, die in einem Werkzeug (`untgz`) steckt, das die Runtime nicht
  baut, und das Manifest sagt das nicht.
- Die NVD ist langsam und ratenbegrenzt: 5 Anfragen in 30 Sekunden ohne
  API-Schlüssel und 50 mit einem. Eine Installation hat Hunderte
  unterschiedlicher Komponenten, daher dauert ein erster Lauf ohne Schlüssel
  eine Stunde oder mehr und mit Schlüssel mehrere Minuten
  (`[sources.nvd] api_key_file`). Antworten werden einen Tag aufbewahrt und
  eine Woche genutzt, wenn die NVD nicht erreichbar ist, spätere Läufe sind
  also schnell.
- Eine Komponente, für die die NVD nicht antworten konnte (eine fehlgeschlagene
  Anfrage, ein Ratenlimit, eine abgeschnittene Liste), wird im Detail der
  Quelle genannt, die Quelle ist `failed`, und mit `required = true` ist das
  Ergebnis unvollständig (Exit 2). Das wird nie als „keine CVEs“ gelesen.
- Runtimes ohne `manifest.json` (Erweiterungen für Locales, GL-Treiber und
  Codecs) werden in einem einzigen `unresolved`-Eintrag gezählt. Die
  Anwendungen selbst werden nicht gelesen: Sie bündeln ihre eigenen
  Bibliotheken und tragen kein solches Manifest.

## SBOM und VEX

`amivuln --all -f cyclonedx` schreibt ein CycloneDX-1.6-Dokument: Jedes
installierte Paket ist eine Komponente, mit seiner purl und der Art, wie es
identifiziert wurde (`amivuln:provenance`), und jeder Fund ist eine
Schwachstelle mit ihrer Analyse. `amivuln --all -f openvex` schreibt ein
OpenVEX-0.2.0-Dokument mit einer Aussage pro Paket und CVE. Beide gelten für
`check`; `pending`, `cve` und `restart` lehnen sie ab.

Der Zustand stammt aus den eigenen Daten der Distribution:

- betroffen, mit der Version, die es behebt, wenn eine veröffentlicht ist:
  `exploitable` in CycloneDX, `affected` in OpenVEX;
- behoben in oder vor der installierten Version, einschließlich Behebungen, die
  eine Distribution zurückportiert hat: `resolved` und `fixed`;
- als nicht betroffen erklärt, von der Distribution oder durch eine VEX-Datei,
  die Sie mit `--vex` übergeben haben: `not_affected` in beiden, mit der
  Begründung;
- nicht verifizierbar (keine Aussage der Distribution oder nicht vergleichbare
  Versionen): `in_triage` und `under_investigation`.

Welche davon erscheinen, hängt davon ab, was die Quelle auflistet. Fedoras
`updateinfo` und der Arch Security Tracker listen, was sie behoben haben, dort
tauchen behobene CVEs also auf. OSV wird zur installierten Version befragt,
daher listen die Dokumente auf Debian-, Ubuntu-, Alpine- und Red-Hat-Hosts die
offenen Probleme, nicht die bereits geschlossenen.

Die Aussagen sind die Einschätzung dieses Werkzeugs für diesen Host, keine
Bescheinigung der Distribution. Ein unvollständiger Lauf wird in den
CycloneDX-Metadaten mit `amivuln:complete = false` markiert, und ein Paket, das
amivuln nicht auflösen konnte, wird in `amivuln:unresolved` gezählt; der
Exit-Code ist wie üblich 2. Die Ausgabe ist deterministisch: Komponenten und
Aussagen sind nach purl sortiert, und es wird nichts Zufälliges (keine
Seriennummer) hinzugefügt. Die Tests validieren beide Dokumente gegen die
offiziellen Schemas.

## Prometheus und der Textfile-Collector von node_exporter

`amivuln --all -f prometheus` schreibt Textmetriken:
`amivuln_findings{severity,kev}`, `amivuln_unverified_findings`,
`amivuln_source_up{source}`, `amivuln_source_age_seconds{source}`,
`amivuln_run_complete` und `amivuln_last_run_timestamp_seconds`. Die Labels
stammen aus festen Vokabularen, sodass kein Paketname, Hostname oder Pfad den
Metrikspeicher erreicht. Schreiben Sie die Ausgabe über eine temporäre Datei
und ein Rename in eine `.prom`-Datei im Textfile-Verzeichnis, damit der
Collector nie eine unvollständige Datei liest.

## Zeitgesteuert laufen lassen

`contrib/systemd/amivuln.service` und `amivuln.timer` scannen den Host alle
sechs Stunden und schreiben `amivuln.prom` für den Textfile-Collector, über
`--output`, damit die Datei atomar ersetzt wird. Der Dienst läuft als
dynamischer Benutzer ohne Capabilities, mit schreibgeschütztem Dateisystem und
einem Systemaufruf-Filter; `systemd-analyze security amivuln.service` meldet
eine Exposition von 1.2.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Passen Sie `ExecStart` und `ReadWritePaths` an, wenn das Textfile-Verzeichnis
abweicht. Die Exit-Codes 1 (Richtlinie), 2 (unvollständig) und 3 (nicht
aufgelöst) schreiben weiterhin eine gültige Datei, die Unit scheitert also nur
bei einem Aufruf- oder internen Fehler.

## Hinter einem Proxy oder einer Firmen-CA

Setzen Sie die Tabelle `[network]` in der Konfigurationsdatei:

```toml
[network]
proxy = "http://proxy.corp.example:3128"   # Standard: HTTPS_PROXY und NO_PROXY
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
user_agent_suffix = "team-sre"
```

`ca_file` fügt den eingebauten Wurzelzertifikaten weitere vertrauenswürdige
hinzu (PEM, höchstens 1 MiB). `user_agent_suffix` wird an den `User-Agent`
angehängt und ist der einzige hostspezifische Text, der den Rechner verlassen
kann, und nur, wenn Sie ihn setzen. Eine Proxy-URL darf Zugangsdaten enthalten;
amivuln gibt sie nie aus. Um stattdessen einen internen Mirror zu verwenden,
setzen Sie `sources.<name>.url`.

## Für KI-Agenten: der MCP-Server

`amivuln mcp` spricht das Model Context Protocol über stdio (zeilenweise
getrenntes JSON-RPC 2.0, Protokollrevisionen 2025-06-18, 2025-03-26 und
2024-11-05). Registrieren Sie ihn in einem Client wie folgt:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

Die Werkzeuge sind schreibgeschützt, und jedes führt eine feste Kommandozeile
mit `-f json` aus; das Ergebnis ist derselbe versionierte Bericht, den die
Kommandozeile ausgibt.

- `check_target`: `targets` (1 bis 20 Paketnamen, `name@version` oder `pkg:`-URLs) und eine optionale `distro`.
- `check_cve`: `id` wie `CVE-2024-6387`; scannt jedes installierte Paket.
- `pending_updates`, `needs_restart` und `list_services`: keine Argumente.

Es gibt keine Shell, keine Eingabe von Dateipfaden und keine Möglichkeit,
Optionen zu übergeben: Ein Ziel, das mit `-` beginnt oder Steuerzeichen
enthält, wird abgelehnt. Der Server aktualisiert den lokalen Cache wie jeder
andere Lauf; übergeben Sie `--offline` oder `--no-cache` an `amivuln mcp`, um
das einzuschränken. Lesen Sie in einem Ergebnis immer `complete` und `sources`,
bevor Sie eine leere Liste als sauber behandeln.

## Ein SBOM prüfen

`amivuln --sbom bom.cdx.json --distro fedora:44 --fail-on high` liest ein
CycloneDX-JSON-Dokument (jede 1.x), prüft jede Komponente, deren purl ein
`rpm`-, `deb`- oder `alpm`-Paket ist, und lässt den Host in Ruhe. Eine purl,
deren Namespace nicht zu `--distro` passt, ist ein Fehler. Komponenten, die
keine OS-Pakete sind (npm, PyPI, Maven und so weiter), werden nicht stillschweigend
verworfen: Sie erscheinen als `unresolved`-Einträge, einer pro purl-Typ mit
einer Anzahl, und der Lauf endet mit 3. Um nur OS-Pakete zu prüfen, filtern Sie
das SBOM zuerst, zum Beispiel mit
`jq '.components |= map(select(.purl // "" | startswith("pkg:rpm/")))'`.

## Robuste Netzwerke

Quellen können Mirrors haben. Eine Quelle, die an ihrem primären Endpunkt
scheitert, wird in der geschriebenen Reihenfolge an jedem Mirror in `fallback`
erneut befragt, bevor sie als fehlgeschlagen zählt. Jeder fehlschlagende Aufruf
wird mit exponentiellem Backoff und Jitter wiederholt (`retries`, Standard 2,
höchstens 10); ein vom Server gesendetes `Retry-After` wird innerhalb des
Wiederholungsbudgets beachtet. Ein Endpunkt, der wiederholt scheitert, löst
einen Circuit Breaker pro Endpunkt aus und wird für den Rest eines Laufs
übersprungen (`cooldown`, standardmäßig 30 s), sodass ein toter Mirror den Scan
nicht aufhält. Ein langsamer Host kann mit `min_interval` bewusst gebremst
werden, das Anfragen an denselben Host staffelt (zum Beispiel `"100ms"`).

Die Reihenfolge der Ausweichstufen ist: primärer Endpunkt, dann Mirrors, dann
der Cache, dann die installierte Offline-Datenbank (siehe den Abschnitt zur
Offline-Datenbank), dann Fehlschlag. `sources` in jeder Ausgabe sagt, welche
davon geantwortet haben, wie alt sie sind und ob das Ergebnis vollständig ist.

## Webhook-Benachrichtigungen

Ein Abschnitt `[notify]` sendet nach einem `check`-Lauf eine kompakte
Zusammenfassung: Host-Fakten, Vollständigkeit, Note, Summen, Fund-IDs. Er ist
opt-in und enthält nichts, was der JSON-Bericht nicht ohnehin angibt.

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"   # jeder Endpunkt, der einen POST akzeptiert
bearer_file = "/etc/amivuln/notify-token"   # optional; gesendet als Authorization: Bearer
on = "violation"                            # violation (Standard) | incomplete | always
```

Eine fehlgeschlagene Zustellung gibt eine Warnung aus und ändert nie den
Exit-Code: Die Richtlinienentscheidung wurde aus dem Scan getroffen, nicht aus
der Benachrichtigung.


## Die Offline-Datenbank

`amivuln db` bewegt Advisory-Daten zwischen Hosts, die das Netzwerk erreichen
dürfen, und Hosts, die das nicht dürfen. Das Archiv ist ein `tar.zst` mit dem
SQLite-Cache und einem Manifest mit einem SHA-256 der Datenbank; `--key` und
`--sig` fügen eine minisign-Signatur über das Manifest hinzu.

```bash
amivuln --all -f json            # den Cache aufwärmen (braucht einmal das Netzwerk)
amivuln db build --archive db.tar.zst
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst       # prüfen und für diesen Benutzer installieren
amivuln db info db.tar.zst
```

`db pull` installiert unter `$XDG_DATA_HOME/amivuln/offline` und lehnt ein
Archiv ab, das älter als das installierte ist (Anti-Rollback); `--force`
überschreibt das. Nach der Installation antwortet ein Lauf mit `--offline`
daraus und meldet diese Quellen als `stale`, sodass ein Host mit Luftspalt
dieselben Berichtsformen erzeugt, mit Exit-Codes, die weiterhin `--fail-on`
respektieren. `amivuln db verify` endet mit 65, wenn ein Archiv manipuliert
ist; ein rückschrittliches `db pull` endet ebenfalls mit 65.

Signieren ist bewusst nicht eingebaut: Erzeugen Sie den Projektschlüssel mit
dem Werkzeug `minisign` und signieren Sie außerhalb von amivuln
(`minisign -S -s key.sec -m manifest.json -x db.tar.zst.minisig`), damit der
geheime Schlüssel nie durch dieses Binary läuft.

## Dateien, die keinem Paket gehören

Ein Pfadziel, das die Paketverwaltung nicht kennt (ein in einen Container
kopiertes Binary, mitgelieferte Software), wird anhand seiner eigenen
systemd-`.note.package` identifiziert, wenn es eine hat. Paket, Version und
Paketsystem stammen aus der Datei, und der Bericht markiert das Paket mit der
Provenienz `embedded_note`. Ein Hinweis für ein anderes Paketsystem als das des
Hosts (ein `deb`-Hinweis auf einem RPM-Host) wird als nicht aufgelöst
abgelehnt, statt geraten zu werden, und die Datei wird nie ausgeführt.

## Go- und Rust-Programme, die niemandem gehören

Gehört ein Pfadziel keinem Paket und hat keinen Paket-Hinweis, liest amivuln
die Go-Module (Build-Informationen) oder Rust-Crates (cargo-auditable-Daten),
die das Programm deklariert, und fragt OSV zu jeder exakten Version. Funde
zeigen die niedrigste behobene Version oberhalb der installierten, und
`update_hint` sagt, dass das Programm neu gebaut werden muss, weil keine
Paketverwaltung eine statisch gelinkte Abhängigkeit aktualisieren kann.
Dateien, die einem Paket gehören, werden bewusst nicht auf diese Weise
aufgefächert: Eine Distribution portiert Behebungen in mitgelieferten Code
zurück, ohne Versionen zu ändern, die Modulversionen eines Binarys mit Eigentümer
würden also Falsch-Positive erzeugen.

Der OSV-Endpunkt für diesen Durchgang ist `[sources.osv]` (standardmäßig
erforderlich: Ein fehlgeschlagener Durchgang lässt diese Module unbeurteilt,
und das darf nicht sauber aussehen). Der textuelle Schweregrad stammt aus dem
Advisory, wenn es einen angibt (GitHub-Advisories tun das; RUSTSEC-Einträge
nicht und melden `unknown`).

## Der minisign-Schlüssel des Projekts

`contrib/offline-db/amivuln.pub` ist der öffentliche minisign-Schlüssel des
Projekts. Er wird auch vom nächtlichen Workflow verwendet, um die Datenbank zu
prüfen, bevor sie im Release veröffentlicht wird. Der private Schlüssel des
Projekts liegt nur in den Repository-Secrets (`MINISIGN_SECRET_KEY` plus
`MINISIGN_PASSWORD`) und nie auf einem Entwicklerrechner, sodass ein
kompromittierter Mirror weder Aktualität vortäuschen noch eine alte Datenbank
am Anti-Rollback-Zeitstempel vorbei wieder einspielen kann.


## Einen Container scannen

`amivuln --container ID` prüft die in einem Container installierten Pakete.
Die Laufzeit (podman, dann docker) wird nur aufgerufen, um das Root-Dateisystem
zu exportieren, wobei nie etwas im Container ausgeführt wird. Die eigene
`os-release` des Containers bestimmt das Ökosystem, sodass die Host-Distribution
nie in die Antwort einfließt, und die Pakete werden von der passenden Quelle
beurteilt (OSV für Debian, Ubuntu, Rocky, `AlmaLinux`, Red Hat Enterprise Linux
(UBI eingeschlossen); die rpm-Datenbank über das `rpm` des Hosts für Container
der Fedora-Familie). Funde werden mit der Container-ID gekennzeichnet, zum
Beispiel `web:nginx`.

```bash
amivuln --container web --container db --fail-on high
```

Alpine-Container werden von OSV beurteilt (`Alpine:v3.20` für Release 3.20).
Die installierte Datenbank nennt den Ursprung jedes Unterpakets, und OSV ordnet
Alpine-Advisories nach Ursprung zu, daher wird `libcrypto3` als `openssl`
abgefragt. Edge- und Alpha-Images haben kein OSV-Release und werden abgelehnt.
Versionen folgen der `apk`-Ordnung (`1.0_rc1` vor `1.0`, `-r1` nach `-r0`).

## Versionsbanner in Binaries

Wenn nichts anderes ein Binary identifiziert (kein Paketeigentümer, kein
Paket-Hinweis, keine Go- oder Rust-Metadaten), durchsucht amivuln es nach den
Versionsbannern, die eine kuratierte Menge von C-Produkten ausgibt: OpenSSL,
curl, zlib, SQLite, nginx und andere. Ein Treffer wird zu einem Ziel mit der
Upstream-Version, wie sie ausgegeben wird, und in jedem Format mit
`string_heuristic` markiert.

Das ist ein Signal mit **geringer Verlässlichkeit**: Die Distribution kann
Behebungen zurückportiert haben, ohne das eingebettete Banner zu ändern. Das
Urteil ist echt, aber der Benutzer sollte es anhand des Changelogs der
Distribution überprüfen.

### Die Versionsprobe in der Sandbox

Mit `exec_version_probe = true` in `[general]` führt amivuln zusätzlich
`<file> --version` für Dateien aus, die nichts anderes identifiziert, und liest
die Banner aus dem, was ausgegeben wird. Das ist die einzige Stelle, an der
amivuln ein Ziel ausführt, daher ist es standardmäßig aus und läuft in einer
Sandbox, die vor dem `exec` angewendet wird:

- keine Schreibzugriffe aufs Dateisystem (Landlock), und Lesezugriffe nur auf
  die Systembibliotheksverzeichnisse und das eigene Verzeichnis des Ziels;
- keine Sockets und kein Zugriff auf andere Prozesse (seccomp);
- `no_new_privs`, ein Wechsel zu `nobody`, wenn als root gestartet, 2 s CPU-Zeit,
  kein Dateiwachstum, keine Core-Dumps, 64 offene Dateien;
- 2 s Wanduhrzeit und 64 KiB Ausgabe pro Stream.

Kann der Kernel die Sandbox nicht durchsetzen (kein Landlock oder eine andere
Architektur als x86_64 und aarch64), meldet der Lauf für diese Datei einen
Fehler. Er führt das Ziel nie ohne Einschränkung aus. Der seccomp-Filter ist
eine Sperrliste, keine Erlaubnisliste: Ziele sind beliebige Binaries, deren
Startup-Syscalls sich nicht auflisten lassen, und Landlock nimmt die
Dateisystemseite bereits weg.

## NVD-Ausweichstufe für Produkte ohne Eigentümer

Die Ziele der String-Heuristik (Produkte ohne Distributionsdaten) werden
zusätzlich anhand des CPE-Namens gegen die NVD-2.0-API geprüft. Die
CPE-Zuordnungstabelle ist kuratiert (`nginx` wird auf `f5:nginx` abgebildet,
`curl` auf `haxx:curl`); ein Produkt, das die Tabelle nicht abdeckt, wird
übersprungen. Die Quelle ist optional (`sources.nvd.required = false` ist der
Standard), ein Ausfall macht das Ergebnis also nicht unvollständig. Der
optionale API-Schlüssel hebt das Ratenlimit von 5 auf 50 Anfragen pro 30
Sekunden.

```toml
[sources.nvd]
enabled = true
required = false
# api_key_file = "/etc/amivuln/nvd-api-key"
```

NVD-Funde tragen den CVSS-Schweregrad aus der neuesten verfügbaren
Metrikversion, und das Urteil ist `affected` ohne behobene Version: Die NVD ist
ein CVE-Katalog, keine Quelle für Distributions-Behebungen.
