# FAQ de falsos positivos

**O amivuln relata uma CVE que a minha distribuição já corrigiu.** O status da
distribuição se sobrepõe à comparação de versões, então isso não deveria
acontecer. Abra uma issue de *falso positivo* com a saída de
`amivuln PACKAGE -f json` e o link do advisory ou do changelog que mostra a
correção.

**O amivuln não relata nada, mas eu conheço uma CVE.** No Fedora, Red Hat,
Rocky e AlmaLinux, o amivuln só enxerga correções que foram publicadas. Uma CVE
que ainda não tem atualização não está nos dados, então um resultado nesses
sistemas é um limite inferior. Abra uma issue de *falso negativo* se os dados
tiverem o registro.

**O resultado diz INCOMPLETE.** Uma fonte obrigatória estava inacessível e não
havia cópia em cache dentro de `stale_max_age`. Tente de novo, verifique a rede
ou use um espelho com `sources.distro.url`. O código de saída é 2 de propósito.

**Por que um pacote fica "unverified"?** A distribuição não tem nenhuma
declaração sobre ele. Ele é listado à parte e não reprova um build, a menos que
você passe `--strict`.

**O meu repositório `updates` está desativado.** O amivuln olha os dados
`updates` publicados pelo Fedora, independentemente da configuração dos
repositórios locais, então pode relatar uma atualização que o seu sistema ainda
não enxerga.
