`--format sarif` écrit du SARIF 2.1.0 (un résultat par constat concerné, niveaux `error`/`warning`/`note`) ; `--format csv` écrit une ligne par constat avec chaque champ entre guillemets et une garde `'` avant `= + - @` pour que les tableurs n'exécutent pas de formules ; `--format markdown` écrit un tableau par cible.

# Schéma JSON

`amivuln -f json` écrit un document par exécution. Le schéma est publié sous
[v1.json](https://ibexwall.com/amivuln/schema/v1.json) (servi à l'adresse
`https://ibexwall.com/amivuln/schema/v1.json`) et les tests du projet
valident la sortie réelle contre lui.

Le tableau `suppressed` (tous les documents) liste les constats acceptés. Les
commandes `cve` et `pending` écrivent leurs propres documents (`"kind": "cve"`
et `"kind": "pending"`) avec les schémas
[cve-v1.json](https://ibexwall.com/amivuln/schema/cve-v1.json),
[pending-v1.json](https://ibexwall.com/amivuln/schema/pending-v1.json) et, pour
`restart`, [restart-v1.json](https://ibexwall.com/amivuln/schema/restart-v1.json).
Le rapport d'exécution porte aussi un objet `score`.

Règles :

- `schema_version` est incrémenté à chaque changement incompatible ; ajouter
  des champs facultatifs ne l'incrémente pas.
- `findings` (concernés) et `unverified` sont des tableaux séparés.
- L'`id` d'un constat est un identifiant de CVE, ou un identifiant de mise à
  jour de la distribution quand la mise à jour ne nomme aucune CVE.
- `complete: false` signifie qu'une source requise a échoué. Traitez cela
  comme inconnu, pas comme propre.
- L'objet `host` ne contient jamais que `os_id`, `os_version` et `arch`.

Valider un document :

```bash
check-jsonschema --schemafile v1.json amivuln.json
```
