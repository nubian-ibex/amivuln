`--format sarif` grava SARIF 2.1.0 (um resultado por achado afetado, níveis `error`/`warning`/`note`); `--format csv` grava uma linha por achado com todos os campos entre aspas e uma proteção `'` antes de `= + - @` para que planilhas não executem fórmulas; `--format markdown` grava uma tabela por alvo.

# Esquema JSON

`amivuln -f json` grava um documento por execução. O esquema é publicado como
[v1.json](https://ibexwall.com/amivuln/schema/v1.json) (também servido em
`https://ibexwall.com/amivuln/schema/v1.json`) e os testes do projeto
validam a saída real contra ele.

O array `suppressed` (todos os documentos) lista os achados aceitos. Os
comandos `cve` e `pending` gravam documentos próprios (`"kind": "cve"` e `"kind": "pending"`) com os esquemas [cve-v1.json](https://ibexwall.com/amivuln/schema/cve-v1.json), [pending-v1.json](https://ibexwall.com/amivuln/schema/pending-v1.json) e, para `restart`, [restart-v1.json](https://ibexwall.com/amivuln/schema/restart-v1.json). O relatório da execução também traz um objeto `score`.

Regras:

- `schema_version` é incrementada a cada mudança incompatível; adicionar
  campos opcionais não a incrementa.
- `findings` (afetados) e `unverified` são arrays separados.
- O `id` de um achado é um id de CVE, ou o id de uma atualização da
  distribuição quando a atualização não nomeia nenhuma CVE.
- `complete: false` significa que uma fonte obrigatória falhou. Trate como
  desconhecido, não como limpo.
- O objeto `host` contém apenas `os_id`, `os_version` e `arch`.

Valide um documento:

```bash
check-jsonschema --schemafile v1.json amivuln.json
```
