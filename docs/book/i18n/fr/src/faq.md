# FAQ des faux positifs

**amivuln signale une CVE que ma distribution a déjà corrigée.** Le statut de
la distribution l'emporte sur la comparaison des versions, donc cela ne devrait
pas arriver. Ouvrez un ticket *false positive* avec la sortie de
`amivuln PACKAGE -f json` et le lien vers l'avis ou le journal des changements
qui montre le correctif.

**amivuln ne signale rien, mais je connais une CVE.** Sur Fedora, Red Hat,
Rocky et AlmaLinux, amivuln ne voit que les correctifs publiés. Une CVE sans
mise à jour pour l'instant n'est pas dans les données : un résultat vide est
donc une borne inférieure. Ouvrez un ticket *false negative* si les données
contiennent bien l'enregistrement.

**Le résultat indique INCOMPLETE.** Une source obligatoire était injoignable et
aucune copie en cache n'était assez récente pour respecter `stale_max_age`.
Réessayez, vérifiez le réseau ou utilisez un miroir avec `sources.distro.url`.
Le code de sortie est 2 volontairement.

**Pourquoi un paquet est-il « unverified » ?** La distribution ne dit rien à
son sujet. Il est listé à part et ne fait pas échouer un build, sauf si vous
passez `--strict`.

**Mon dépôt `updates` est désactivé.** amivuln consulte les données `updates`
publiées par Fedora, quelle que soit la configuration de vos dépôts locaux ; il
peut donc signaler une mise à jour que votre système ne voit pas encore.
