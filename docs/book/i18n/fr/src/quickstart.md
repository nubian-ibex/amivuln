# Démarrage rapide

```bash
amivuln nginx                          # un paquet installé
amivuln /usr/sbin/nginx                # le paquet auquel appartient un fichier
amivuln nginx.service                  # le paquet derrière une unité systemd
amivuln openssl@3.5.1-1 --distro arch  # une version, sans lire l'hôte
amivuln --all                          # tous les paquets installés
```

## Questions sur l'hôte entier

```bash
amivuln cve CVE-2024-6387      # un paquet installé est-il concerné ?
amivuln pending                # quelles mises à jour réduisent le plus le risque, les plus risquées d'abord
amivuln services               # vérifie le paquet derrière chaque service en cours d'exécution
amivuln restart                # quels processus utilisent encore des fichiers remplacés par une mise à jour
amivuln --packages-from list.txt   # vérifie une liste de paquets exportée depuis un autre hôte
```

`cve` se termine par le code 1 lorsqu'un paquet est concerné. Quand les données
de la distribution n'ont aucune trace de la CVE, il le dit explicitement : ce
n'est pas une affirmation que l'hôte est sûr. `pending` regroupe en une seule
mise à jour les sous-paquets construits à partir d'une même source et classe
selon les failles exploitées (KEV), la gravité et l'EPSS. `restart` lit `/proc`
(exécutez-le en root pour voir tous les processus ; la sortie indique combien
n'ont pu être inspectés) et se termine par le code 1 quand quelque chose doit
être redémarré. `services` liste les services systemd en cours d'exécution qui
ne viennent pas d'un paquet, sans faire échouer l'exécution. Une analyse du
système entier affiche aussi une note de l'hôte de A à F (voir l'ADR-0011 dans
le dépôt).

## Lire le résultat

Pour chaque paquet, vous obtenez le nombre de constats concernés par gravité,
combien sont connus pour être exploités (CISA KEV), le score EPSS le plus élevé
et la version qui les corrige, avec la commande que vous exécuteriez. amivuln
n'exécute jamais cette commande.

Les constats que la distribution ne peut pas confirmer sont listés à part comme
*non vérifiés* et ne sont pas comptés avec les constats concernés.

## Faire échouer un build

```bash
amivuln --all --fail-on high           # code 1 pour HIGH ou pire
amivuln --all --fail-on kev            # code 1 uniquement pour les CVE exploitées
amivuln --all -f sarif > amivuln.sarif # SARIF 2.1.0 pour le code scanning
amivuln --all -f csv > amivuln.csv     # sûr pour les tableurs (injection de formules bloquée)
```

Codes de sortie : `0` propre, `1` constats au niveau de `--fail-on` ou au-dessus,
`2` incomplet, `3` cible non résolue, `64` erreur d'usage, `70` erreur interne.
Le code `2` empêche une panne des données de sécurité de passer pour une
analyse propre.

## Une étape GitHub Actions

L'[amivuln-action](https://github.com/nubian-ibex/amivuln-action) télécharge une
version, vérifie son attestation et sa somme de contrôle, puis l'exécute.
Épinglez-la sur un SHA de commit complet :

```yaml
permissions:
  contents: read
  attestations: read
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high
```

Les mêmes étapes, à la main :

```yaml
- name: Télécharger amivuln
  run: |
    gh release download --repo nubian-ibex/amivuln --pattern 'amivuln-x86_64-unknown-linux-musl.tar.zst'
    gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
    tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
- name: Vérifier les paquets
  run: ./amivuln --all --fail-on high
```

Voir aussi [Utiliser amivuln](using.md) pour d'autres scénarios.
