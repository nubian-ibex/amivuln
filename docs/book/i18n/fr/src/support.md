# Politique de support

## Versions

Avant la 1.0, seule la dernière version reçoit des correctifs, de sécurité ou
autres. À partir de la 1.0, la dernière version mineure reçoit les correctifs
de sécurité, et un correctif de sécurité est rétroporté vers la version mineure
précédente pendant 90 jours après la sortie d'une nouvelle version mineure.

## Version minimale de Rust prise en charge

La MSRV est le `rust-version` de `Cargo.toml` (1.97 aujourd'hui) et le job CI
`msrv` compile avec elle à chaque changement. Elle n'est relevée que dans une
version mineure, jamais dans une version corrective, et chaque relèvement est
signalé dans le journal des modifications.

## Ce qui constitue un contrat

Le contrat est la commande `amivuln`. Les crates de bibliothèque dont elle est
faite (`amivuln-core`, `-resolve`, `-version`, `-sources`, `-cache`, `-report`,
`-sandbox`) ne sont publiées que parce que le binaire en dépend. Elles
partagent son numéro de version, y compris la 1.0, et elles ne portent
**aucune** promesse de stabilité d'API, à la 1.0 comme après : une version
corrective peut modifier ou supprimer leurs éléments publics. Dépendez-en à vos
risques, ou exécutez la commande et lisez son JSON.

- **Sortie JSON.** Les documents portent `schema_version`. Au sein d'une
  version, les champs ne sont jamais supprimés, renommés ni changés de type ;
  un nouveau champ ou une nouvelle valeur d'énumération est un changement
  additif et paraît dans une version mineure, avec une note dans le journal des
  modifications et le [schéma](json-schema.md)
  publié. Casser la forme implique une nouvelle `schema_version`. Les documents
  de référence sous `tests/golden` figent la sortie exacte, ordre des champs
  compris, et doivent continuer à être validés par le schéma actuel ; un
  changement à ces documents est visible en revue.
- **Codes de sortie.** 0, 1, 2, 3, 64, 65 et 70 et leur précédence sont stables.
- **Configuration.** Les clés ne sont ni supprimées ni renommées au sein d'une
  version majeure ; les nouvelles clés ont des valeurs par défaut qui
  conservent le comportement actuel.
- **Ligne de commande.** Les options ne sont ni supprimées ni détournées de
  leur usage au sein d'une version majeure. La sortie texte (`summary`,
  `detail`) s'adresse aux humains et peut changer.

### Comment le contrat est vérifié

Chaque promesse a un test qui échoue quand elle est rompue par accident :

- chaque valeur que l'outil peut écrire (chaque écosystème, source,
  provenance, sévérité, état et la `mitigation` facultative) est validée
  contre les schémas publiés de `check`, `pending` et `cve` ; les listes sont
  des `match` exhaustifs, de sorte qu'une nouvelle valeur d'énumération
  empêche la compilation tant que le schéma et le test ne la connaissent pas ;
- les documents JSON de référence figent la sortie exacte de `check` ;
- la configuration par défaut est un fichier de référence, et chaque clé
  facultative que nomme `config init` est rechargée (une clé renommée ou
  supprimée échoue) ;
- les codes de sortie sont vérifiés par leur valeur ;
- la page de manuel et les complétions du shell sont générées à partir de la
  ligne de commande et comparées en CI, de sorte qu'une option supprimée ou
  renommée apparaît comme une différence.

Ajouter à un ensemble fermé (un nouvel écosystème, une nouvelle source) est un
changement additif et paraît dans une version mineure ; le schéma et le journal
des modifications le nomment.

## Plateformes

Linux sur x86_64 et aarch64 (builds statiques `musl` et `glibc`). macOS et
Windows ne sont pas pris en charge. Les distributions jugées, et la manière
dont elles le sont, figurent dans
[Sources de données](sources.md#distributions-prises-en-charge).
