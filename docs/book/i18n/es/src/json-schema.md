# Esquema JSON

`amivuln -f json` escribe un documento por ejecución. El esquema se publica como
[v1.json](https://ibexwall.com/amivuln/schema/v1.json) (también servido en
`https://ibexwall.com/amivuln/schema/v1.json`) y las pruebas del proyecto
validan la salida real con él.

El array `suppressed` (todos los documentos) lista los hallazgos aceptados. Los
comandos `cve` y `pending` escriben sus propios documentos (`"kind": "cve"` y
`"kind": "pending"`) con los esquemas [cve-v1.json](https://ibexwall.com/amivuln/schema/cve-v1.json), [pending-v1.json](https://ibexwall.com/amivuln/schema/pending-v1.json) y, para `restart`, [restart-v1.json](https://ibexwall.com/amivuln/schema/restart-v1.json). El informe de la ejecución también incluye un objeto `score`.

Reglas:

- `schema_version` se incrementa en cada cambio incompatible; añadir campos
  opcionales no lo incrementa.
- `findings` (afectados) y `unverified` son arrays separados.
- El `id` de un hallazgo es un id de CVE, o un id de actualización de la
  distribución cuando la actualización no nombra ninguna CVE.
- `complete: false` significa que falló una fuente obligatoria. Trátelo como
  desconocido, no como limpio.
- El objeto `host` solo contiene `os_id`, `os_version` y `arch`.

Valide un documento:

```bash
check-jsonschema --schemafile v1.json amivuln.json
```
