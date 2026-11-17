# Support-Richtlinie

## Versionen

Vor 1.0 erhält nur das neueste Release Korrekturen, ob sicherheitsrelevant
oder nicht. Ab 1.0 erhält das neueste Minor-Release Sicherheitskorrekturen,
und eine Sicherheitskorrektur wird nach dem Erscheinen eines neuen Minor-Releases
90 Tage lang in das vorherige Minor-Release zurückportiert.

## Minimal unterstützte Rust-Version

Die MSRV ist die `rust-version` in `Cargo.toml` (heute 1.97), und der
CI-Job `msrv` baut bei jeder Änderung damit. Sie wird nur in einem
Minor-Release angehoben, nie in einem Patch-Release, und jede Anhebung wird im
Changelog genannt.

## Was ein Vertrag ist

Der Vertrag ist der Befehl `amivuln`. Die Bibliotheks-Crates, aus denen er
gebaut wird (`amivuln-core`, `-resolve`, `-version`, `-sources`, `-cache`,
`-report`, `-sandbox`), werden nur veröffentlicht, weil das Binary von ihnen
abhängt. Sie teilen sich seine Versionsnummer, auch bei 1.0, und tragen **kein**
API-Stabilitätsversprechen, weder bei 1.0 noch danach: Ein Patch-Release darf
ihre öffentlichen Elemente ändern oder entfernen. Verwenden Sie sie auf eigenes
Risiko, oder führen Sie den Befehl aus und lesen Sie sein JSON.

- **JSON-Ausgabe.** Dokumente tragen `schema_version`. Innerhalb einer Version
  werden Felder nie entfernt, umbenannt oder im Typ geändert; ein neues Feld
  oder ein neuer Enum-Wert ist eine additive Änderung und erscheint in einem
  Minor-Release mit einem Hinweis im Changelog und im veröffentlichten
  [Schema](json-schema.md). Eine Änderung der Form bedeutet eine neue
  `schema_version`. Die Golden-Dokumente unter `tests/golden` legen die
  exakte Ausgabe fest, einschließlich der Feldreihenfolge, und müssen weiter
  gegen das aktuelle Schema validieren; eine Änderung daran ist im Review
  sichtbar.
- **Exit-Codes.** 0, 1, 2, 3, 64, 65 und 70 und ihre Rangfolge sind stabil.
- **Konfiguration.** Schlüssel werden innerhalb einer Hauptversion nicht
  entfernt oder umbenannt; neue Schlüssel haben Standardwerte, die das heutige
  Verhalten beibehalten.
- **Kommandozeile.** Flags werden innerhalb einer Hauptversion nicht entfernt
  oder umgewidmet. Die Textausgabe (`summary`, `detail`) richtet sich an
  Menschen und kann sich ändern.

### Wie der Vertrag geprüft wird

Jedes Versprechen hat einen Test, der fehlschlägt, wenn es versehentlich
gebrochen wird:

- Jeder Wert, den das Werkzeug schreiben kann (jedes Ökosystem, jede Quelle,
  Provenienz, Schweregrad, Zustand und das optionale `mitigation`), wird gegen
  die veröffentlichten Schemas von `check`, `pending` und `cve` validiert; die
  Listen sind erschöpfende `match`-Ausdrücke, sodass ein neuer Enum-Wert nicht
  mehr kompiliert, bis Schema und Test ihn kennen;
- die Golden-JSON-Dokumente legen die exakte Ausgabe von `check` fest;
- die Standardkonfiguration ist eine Golden-Datei, und jeder optionale
  Schlüssel, den `config init` nennt, wird zurückgeladen (ein umbenannter oder
  entfernter Schlüssel schlägt fehl);
- die Exit-Codes werden per Wert geprüft;
- die Handbuchseite und die Shell-Vervollständigungen werden aus der
  Kommandozeile erzeugt und in der CI verglichen, sodass ein entferntes oder
  umbenanntes Flag als Diff sichtbar wird.

Das Erweitern einer geschlossenen Menge (ein neues Ökosystem, eine neue
Quelle) ist eine additive Änderung und erscheint in einem Minor-Release;
Schema und Changelog nennen sie.

## Plattformen

Linux auf x86_64 und aarch64 (statische Builds mit `musl` und `glibc`). macOS
und Windows werden nicht unterstützt. Welche Distributionen beurteilt werden
und wie, steht unter [Datenquellen](sources.md#unterstützte-distributionen).
