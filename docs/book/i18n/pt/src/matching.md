# Como a correspondência funciona

Todo veredito responde a uma pergunta: dada a versão instalada de um pacote e
tudo o que as fontes consultadas disseram sobre ele, o host é afetado?

## A distribuição vence

Os dados de advisories da própria distribuição decidem. Intervalos do upstream
nunca são usados para considerar um pacote afetado: as distribuições entregam
correções sem mudar a versão do upstream, então um intervalo do upstream
geraria falsos positivos tanto em sistemas baseados em RPM quanto em sistemas
baseados em Debian.

## Precedência

Por CVE e por pacote, as declarações são combinadas, da mais restritiva para a
menos:

1. **not-affected** vindo da distribuição ou de uma declaração OpenVEX
   (`--vex`), com a justificativa levada a todos os formatos de saída.
2. **patched** (corrigido), quando a versão instalada é igual ou superior à
   correção publicada.
3. **affected** (afetado), caso contrário; o achado informa a versão que o
   corrige.
4. **unverified** (não verificado), quando há um registro mas nenhuma versão
   comparável: a distribuição diz *will not fix* ou *fix deferred* (o relatório
   o lista sob o próprio id), ou a versão corrigida não pode ser comparada com
   a versão instalada (uma correção rpm contra uma instalação deb, por
   exemplo).

Tudo o que uma fonte não soube responder é listado à parte como `unverified` e
nunca é contado silenciosamente como afetado. O enriquecimento (KEV, EPSS)
nunca altera um veredito.

## Por fonte

- **Fedora.** O `updateinfo` publica a versão que corrigiu a CVE. Instalada em
  versão igual ou superior a qualquer correção publicada, está corrigida. Uma
  CVE sem correção publicada não é visível nesses dados.
- **Arch.** O tracker registra um build; a mesma versão do upstream é
  vulnerável, um rebuild dela também, e uma versão mais nova é *não
  verificada*.
- **Debian, Ubuntu, Alpine, openSUSE, Red Hat, Rocky, `AlmaLinux`, módulos Go e
  crates Rust.** O OSV serializa os advisories por ecossistema; as versões
  corrigidas que nomeiam o pacote decidem. Quando vários advisories corrigem
  uma CVE (a Red Hat emite um por stream menor), instalada em versão igual ou
  superior a qualquer um deles, está corrigida. Um registro que o OSV
  associou à versão instalada mas que não lista nenhuma correção é um problema
  em aberto: afetado, sem versão para a qual migrar (o Debian e o Ubuntu têm
  esses registros; Alpine e Red Hat só listam advisories que entregaram uma
  correção; openSUSE também). Alpine, Debian, Ubuntu e openSUSE são consultados
  por pacote-fonte. Para pacotes de linguagens, o OSV responde por versão
  exata, então todo advisory retornado afeta a versão consultada e a correção
  relatada é a menor acima dela. Um advisory de linguagem sem alias de CVE é
  relatado sob o próprio id (GHSA, GO, RUSTSEC) em vez de desaparecer.
- **Baseline.** `--baseline prev.json` mantém apenas os achados novos desde
  esse relatório; nunca transforma uma chamada de afetado em limpo.
- **Arquivo de ignorados.** Um achado aceito é suprimido, com o motivo, o
  responsável e a validade mostrados na saída; uma entrada expirada é um erro.

## Determinismo

As regras são funções puras em `amivuln_core` (`matching::merge`): duas
execuções sobre os mesmos dados concordam, e o corpus de verdade de referência
(casos de Fedora e Arch com fixtures HTTP gravadas) as fixa contra dados
gravados.
