# Comment fonctionne la correspondance

Chaque verdict répond à une seule question : étant donné la version installée
d'un paquet et tout ce que les sources consultées en ont dit, l'hôte est-il
concerné ?

## La distribution l'emporte

Les données d'avis propres à la distribution décident. Les plages amont ne
servent jamais à déclarer un paquet concerné : les distributeurs livrent des
correctifs sans changer la version amont, si bien qu'une plage amont
produirait des faux positifs aussi bien sur les systèmes basés sur RPM que sur
ceux basés sur Debian.

## Précédence

Par CVE et par paquet, les déclarations sont fusionnées, la plus restrictive
d'abord :

1. **not-affected** de la distribution ou d'une déclaration OpenVEX (`--vex`),
   avec la justification reprise dans tous les formats de sortie.
2. **patched** (corrigé), quand la version installée est égale ou supérieure au
   correctif publié.
3. **affected** (concerné), sinon ; le constat nomme la version qui corrige.
4. **unverified** (non vérifié), quand il existe un enregistrement mais aucune
   version comparable : la distribution indique *will not fix* ou *fix
   deferred* (le rapporteur le liste sous son propre identifiant), ou la
   version corrigée ne peut pas être comparée à la version installée (un
   correctif rpm face à une installation deb, par exemple).

Tout ce à quoi une source n'a pas pu répondre est listé séparément comme
`unverified` et jamais compté silencieusement comme concerné. L'enrichissement
(KEV, EPSS) ne change jamais un verdict.

## Par source

- **Fedora.** `updateinfo` publie la version qui a corrigé la CVE. Une version
  installée égale ou supérieure à un correctif publié est corrigée. Une CVE
  sans correctif publié n'est pas visible dans ces données.
- **Arch.** Le tracker enregistre un build ; la même version amont est
  vulnérable, une reconstruction de celle-ci aussi, et une version plus
  récente est *non vérifiée*.
- **Debian, Ubuntu, Alpine, openSUSE, Red Hat, Rocky, `AlmaLinux`, modules Go
  et crates Rust.** OSV sérialise les avis par écosystème ; les versions
  corrigées qui nomment le paquet décident. Quand plusieurs avis corrigent une
  même CVE (Red Hat en publie un par flux mineur), une version installée égale
  ou supérieure à l'un d'eux est corrigée. Un enregistrement qu'OSV a associé à
  la version installée mais qui ne liste aucun correctif est un problème
  ouvert : concerné, sans version vers laquelle migrer (Debian et Ubuntu ont de
  tels enregistrements ; Alpine et Red Hat ne listent que les avis qui ont
  livré un correctif ; openSUSE de même). Alpine, Debian, Ubuntu et openSUSE
  sont interrogés par paquet source. Pour les paquets de langage, OSV répond
  par version exacte : chaque avis renvoyé affecte la version interrogée et le
  correctif indiqué est le plus bas au-dessus d'elle. Un avis de langage sans
  alias CVE est signalé sous son propre identifiant (GHSA, GO, RUSTSEC) au lieu
  de disparaître.
- **Baseline.** `--baseline prev.json` ne conserve que les constats nouveaux
  depuis ce rapport ; il ne transforme jamais un verdict concerné en propre.
- **Fichier d'ignorés.** Un constat accepté est supprimé, avec sa raison, son
  responsable et son expiration affichés dans la sortie ; une entrée expirée
  est une erreur.

## Déterminisme

Les règles sont des fonctions pures dans `amivuln_core` (`matching::merge`) :
deux exécutions sur les mêmes données concordent, et le corpus de vérité
terrain (cas Fedora et Arch avec des fixtures HTTP enregistrées) les fige
contre des données enregistrées.
