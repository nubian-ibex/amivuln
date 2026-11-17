`--format sarif` schreibt SARIF 2.1.0 (ein Ergebnis pro betroffenem Fund, Stufen `error`/`warning`/`note`); `--format csv` schreibt eine Zeile pro Fund mit jedem Feld in Anführungszeichen und einem `'` vor `= + - @`, damit Tabellenkalkulationen keine Formeln ausführen; `--format markdown` schreibt eine Tabelle pro Ziel.

# JSON-Schema

`amivuln -f json` schreibt pro Lauf ein Dokument. Das Schema ist als
[v1.json](https://ibexwall.com/amivuln/schema/v1.json) veröffentlicht, und die
Tests des Projekts validieren die echte Ausgabe dagegen.

Das Array `suppressed` (alle Dokumente) führt akzeptierte Funde auf. Die Befehle `cve` und `pending` schreiben eigene Dokumente (`"kind": "cve"` und `"kind": "pending"`) mit den Schemas [cve-v1.json](https://ibexwall.com/amivuln/schema/cve-v1.json), [pending-v1.json](https://ibexwall.com/amivuln/schema/pending-v1.json) und, für `restart`, [restart-v1.json](https://ibexwall.com/amivuln/schema/restart-v1.json). Der Laufbericht enthält außerdem ein `score`-Objekt.

Regeln:

- `schema_version` wird bei jeder inkompatiblen Änderung erhöht; das Hinzufügen
  optionaler Felder erhöht sie nicht.
- `findings` (betroffen) und `unverified` sind getrennte Arrays.
- Die `id` eines Funds ist eine CVE-ID oder die Update-ID einer Distribution,
  wenn das Update keine CVE nennt.
- `complete: false` bedeutet, dass eine erforderliche Quelle ausgefallen ist.
  Behandeln Sie das als unbekannt, nicht als sauber.
- Das Objekt `host` enthält ausschließlich `os_id`, `os_version` und `arch`.

Ein Dokument validieren:

```bash
check-jsonschema --schemafile v1.json amivuln.json
```
