# Sicherheitsrichtlinien

## Abhängigkeitsrichtlinie (SCA)

`cargo deny`, `cargo audit` und `cargo vet` laufen bei jedem Pull Request und
in der Release-Pipeline (`just ci`). Der Schwellenwert sind null nicht
deklarierte Funde: Ein Fund zu Advisory, Lizenz oder Herkunft blockiert die
Änderung, sofern er nicht mit einer Begründung in `deny.toml` (Advisories,
Lizenzen) oder `supply-chain/config.toml` (Vet-Ausnahmen) deklariert ist.
Deklarierte Ausnahmen werden bei jedem Release erneut geprüft.

Ein Abhängigkeits-Advisory, das amivuln nicht betrifft, wird in `deny.toml`
mit der Advisory-ID und der Begründung festgehalten, warum es hier nicht
ausnutzbar ist; dieser Eintrag ist die maßgebliche VEX-Aussage des Projekts.
Kein Release wird mit einem nicht deklarierten SCA-Fund ausgeliefert: Die
Prüfungen schlagen im Zweifel fehl (fail closed).

## Richtlinie zur statischen Analyse (SAST)

Der Schwellenwert sind null Funde. `cargo clippy --workspace --all-targets
--all-features -- -D warnings` und `cargo fmt --check` blockieren in
`just ci` jede Änderung. Eine Unterdrückung braucht ein Inline-`#[allow]`,
dessen Kommentar begründet, warum der Fund nicht zutrifft; die Lint-Menge wird
nie gesenkt, damit Code durchkommt.

## Richtlinie zu Geheimnissen

- Keine Zugangsdaten gehören in das Repository oder den Issue-Tracker.
- CI-Zugangsdaten (der minisign-Release-Schlüssel, `MINISIGN_SECRET_KEY` und
  `MINISIGN_PASSWORD`, cosign- und crates.io-Tokens) sind GitHub-Actions-Secrets,
  beschränkt auf die Workflows und die `release`-Umgebung, die sie benötigen,
  und werden nie in Logs ausgegeben.
- Geheimnisse werden rotiert, wenn sich ein Workflow, eine Maschine oder eine
  Person mit Zugriff ändert, und sofort bei Verdacht auf ein Leck; nach einem
  Leck werden die Audit-Logs auf die Verwendung des offengelegten Werts
  geprüft.
- Die lokale Entwicklung braucht keine Zugangsdaten: Die Tests kommen ohne
  Netzwerk aus.

## Zugriffs- und Review-Richtlinie

Nur das Maintainer-Konto hat Schreibzugriff, Tag-Rechte und die Freigabe der
Release-Umgebung. Ein neuer Mitarbeitender wird geprüft, bevor erweiterte
Berechtigungen vergeben werden: Beitragshistorie im Projekt, Sicherheitspraxis
(signierte Commits, Disziplin bei Abhängigkeiten) und eine öffentliche
Identität. Die Rulesets auf `main` und auf `v*`-Tags erzwingen signierte
Commits und blockieren Force-Pushes und Löschungen, unabhängig davon, wer die
Berechtigung hält.

## Test-Richtlinie

Jede größere Änderung ergänzt oder aktualisiert Tests in der automatisierten
Suite; ein Bugfix ergänzt den Regressionstest vor der Korrektur. Tests dürfen
das Netzwerk nicht berühren: HTTP-Verhalten wird durch aufgezeichnete Fixtures
und `wiremock` abgedeckt. Führen Sie `just ci` aus, bevor Sie einen Pull
Request öffnen; die CI führt bei jedem Pull Request die komplette Suite aus,
und der Merge ist blockiert, solange sie fehlschlägt.
