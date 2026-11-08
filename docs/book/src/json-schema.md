# JSON schema

`amivuln -f json` writes one document per run. The schema is published as
[v1.json](schema/v1.json) (also served as
`https://nubian-ibex.github.io/amivuln/schema/v1.json`) and the project's tests
validate the real output against it.

Rules:

- `schema_version` is bumped on every incompatible change; adding optional
  fields does not bump it.
- `findings` (affected) and `unverified` are separate arrays.
- A finding `id` is a CVE id, or a distribution update id when the update
  names no CVE.
- `complete: false` means a required source failed. Treat it as unknown, not
  as clean.
- The `host` object only ever holds `os_id`, `os_version` and `arch`.

Validate a document:

```bash
check-jsonschema --schemafile v1.json amivuln.json
```
