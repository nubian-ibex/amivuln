# Sicherheit und Datenschutz

## Was den Host verlässt

Nur das Ökosystem, der Paketname und die Version, in Anfragen an die unter
[Datenquellen](sources.md) aufgeführten Quellen. EPSS-Anfragen enthalten
CVE-IDs. Es wird nie ein Hostname, Pfad, Benutzername oder eine Adresse
gesendet, und ein Test prüft jede Anfrage darauf. Es gibt keine Telemetrie und
keine Update-Prüfung.

## Wie sich das Werkzeug selbst schützt

- Es führt nie das Ziel-Binary aus. Versionen stammen aus dem Paketmanager.
- Systemwerkzeuge laufen von festen absoluten Pfaden mit geleerter Umgebung,
  `LC_ALL=C`, festen Argumenten, einem Timeout und einer Ausgabebegrenzung.
- Advisory-Daten gelten als nicht vertrauenswürdig: Größen und
  Verschachtelungstiefe sind begrenzt, Bezeichner, die nicht wie CVE-IDs
  aussehen, werden verworfen, und Steuerzeichen erreichen nie das Terminal.
- Die Fedora-Metadaten werden gegen den SHA-256 in `repomd.xml` geprüft, sodass
  ein Mirror, der andere Bytes ausliefert, abgelehnt wird.
- Der Netzwerkzugriff nutzt ausschließlich HTTPS mit rustls und höchstens drei
  Weiterleitungen.

## Eine Schwachstelle melden

Nutzen Sie die private Schwachstellenmeldung von GitHub:
[github.com/nubian-ibex/amivuln/security/advisories/new](https://github.com/nubian-ibex/amivuln/security/advisories/new).
Die Reaktionsziele stehen in der `SECURITY.md` des Repositorys.

## Release-Integrität

Releases werden von GitHub Actions aus einem signierten Tag gebaut und
enthalten Build-Provenance-Attestierungen, eine cosign-Signatur über
`SHA256SUMS` und eine SBOM. Release-Builds sind reproduzierbar, wenn sie in
derselben Umgebung gebaut werden; siehe `docs/reproducible-builds.md` im
Repository.
