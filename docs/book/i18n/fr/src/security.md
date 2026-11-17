# Sécurité et confidentialité

## Ce qui quitte l'hôte

Seuls l'écosystème, le nom du paquet et la version, dans les requêtes vers les
sources listées dans [Sources de données](sources.md). Les requêtes EPSS
portent des identifiants de CVE. Aucun nom d'hôte, chemin, nom d'utilisateur ni
adresse n'est jamais envoyé, et un test inspecte chaque requête pour s'en
assurer. Il n'y a ni télémétrie ni vérification de mise à jour.

## Comment l'outil se protège

- Il n'exécute jamais le binaire cible. Les versions viennent du gestionnaire
  de paquets.
- Les outils système s'exécutent depuis des chemins absolus fixes avec un
  environnement vidé, `LC_ALL=C`, des arguments fixes, un délai d'expiration et
  une limite de sortie.
- Les données d'avis ne sont pas fiables : les tailles et la profondeur
  d'imbrication sont limitées, les identifiants qui ne ressemblent pas à des
  identifiants de CVE sont écartés, et les caractères de contrôle n'atteignent
  jamais le terminal.
- Les métadonnées Fedora sont vérifiées par rapport au SHA-256 de
  `repomd.xml`, de sorte qu'un miroir servant d'autres octets est rejeté.
- L'accès réseau utilise uniquement HTTPS, avec rustls, et au plus trois
  redirections.

## Signaler une vulnérabilité

Utilisez le signalement privé de vulnérabilités de GitHub :
[github.com/nubian-ibex/amivuln/security/advisories/new](https://github.com/nubian-ibex/amivuln/security/advisories/new).
Consultez le `SECURITY.md` du dépôt pour les objectifs de réponse.

## Intégrité des versions

Les versions sont compilées par GitHub Actions à partir d'un tag signé et
livrent des attestations de provenance de build, une signature cosign de
`SHA256SUMS` et un SBOM. Les builds de publication sont reproductibles quand
ils sont compilés dans le même environnement ; voir
`docs/reproducible-builds.md` dans le dépôt.
