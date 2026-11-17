# Fontes de dados

- **Arch Security Tracker**: status das CVEs e versão corrigida no Arch (`https://security.archlinux.org/issues/all.json`)
- **Fedora `updateinfo`**: atualizações de segurança e as CVEs que elas corrigem no Fedora (`https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/<arch>/repodata/`)
- **OSV**: Debian, Ubuntu, Alpine, openSUSE, Red Hat Enterprise Linux, Rocky Linux, `AlmaLinux`, módulos Go e `crates.io` (`https://api.osv.dev/v1/querybatch`, um documento de advisory por id). Advisories que também existem nos trackers das distribuições têm o mesmo significado; para Go e crates, as versões exatas é que decidem.
- **CISA KEV**: CVEs exploradas ativamente (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- **FIRST EPSS**: probabilidade de exploração (`https://api.first.org/data/v1/epss`)

A fonte da distribuição é obrigatória por padrão. KEV e EPSS enriquecem o
resultado e são opcionais: se falharem, a saída diz isso, mas o resultado
continua completo.

## Por que não o OSV para Fedora e Arch

A lista de ecossistemas do OSV (conferida em 2026-11-07) contém Debian, Ubuntu,
Alpine, Red Hat, Rocky, AlmaLinux, SUSE e outros, mas não Fedora nem Arch
Linux. Para esses dois, os dados da própria distribuição são a fonte da
verdade.

## Particularidades do Fedora

O `updateinfo` informa quais CVEs uma atualização corrigiu. O amivuln relata
uma CVE como afetando um pacote instalado quando o Fedora publicou uma correção
em uma versão mais nova. Só são confiáveis os ids de CVE que abrem o título de
um bug do bugzilla; ids que aparecem apenas em descrições de texto livre são
ignorados, porque "regression from the fix for CVE-X" marcaria CVE-X como
corrigida. Uma atualização de segurança que não nomeia nenhuma CVE é relatada
sob o id da atualização. Uma CVE sem correção publicada não é visível nesses
dados.

## Red Hat Enterprise Linux

O RHEL é avaliado a partir do ecossistema `Red Hat` do OSV, que republica os
advisories de segurança da Red Hat (RHSA e RHBA). O OSV registra um pacote sob
o repositório em que ele é distribuído (`Red Hat:enterprise_linux:9::baseos`,
`::appstream`, `::crb`) e o banco de dados do rpm não registra qual é, então o
amivuln consulta os três e combina as respostas. Uma CVE costuma ter várias
correções, uma por stream menor (GA, EUS, E4S). O amivuln segue a regra do
Fedora: uma versão instalada igual ou superior a qualquer correção publicada
está corrigida, e uma mais antiga é relatada contra a menor correção. Um host
que não esteja no stream mais baixo pode, portanto, ver uma correção que não
consegue instalar; o achado informa a versão para que o stream possa ser
verificado.

**CVEs sem correção.** O OSV traz os advisories que entregaram uma correção.
Uma CVE que a Red Hat não corrigiu (`Affected`, `Fix deferred`, `Will not fix`,
`Out of support scope`) não tem advisory ali, então no RHEL 8 e 9 o amivuln
também lê o arquivo OVAL da Red Hat "including unpatched" (ADR-0014, fonte
`redhat-oval`): cerca de 11 MB, lido uma vez a cada atualização do cache e
reduzido a um índice pequeno. Um pacote do host é associado pelo nome do pacote
binário ou do pacote-fonte, e cada CVE encontrada é relatada como afetada sem
versão de correção, nunca como limpa. Uma CVE para a qual o OSV já tem resposta
mantém a resposta do OSV. `Under investigation` não é relatado. O arquivo não
tem estado para o RHEL 10, então a fonte aparece como ignorada ali e o
resultado do RHEL 10 continua sendo um limite inferior. Nada sobre o host é
enviado; desative com `sources.rhel_unpatched.enabled = false`. Os dados são
publicados pela Red Hat sob CC BY 4.0. Os pacotes do kernel aparecem listados
contra centenas de CVEs, a maioria baixa e adiada: é o que a Red Hat diz. A
severidade vem da classificação que a Red Hat vincula em cada advisory
(Important corresponde a high).

## Onde os dados ficam offline

`amivuln db build` empacota tudo o que foi consultado em um `tar.zst` que outro
host verifica, `amivuln db pull`, e consulta com `--offline` (veja o guia). A
entrada VEX vem de documentos que você fornece com `--vex`.

## Distribuições suportadas

Como um alvo é identificado, e o que os dados podem e não podem mostrar:

- **Fedora.** O host é lido por meio do `rpm`. Dados: `updateinfo`. Uma CVE sem correção publicada não é visível.
- **Arch Linux.** O host é lido por meio do `pacman`. Dados: o Arch Security Tracker, que também lista pacotes vulneráveis sem correção.
- **Red Hat Enterprise Linux 8, 9 e 10.** O host é lido por meio do `rpm`; containers UBI funcionam. Dados: o ecossistema Red Hat do OSV, mais as CVEs sem correção do arquivo OVAL da Red Hat no RHEL 8 e 9 (veja abaixo); o RHEL 10 continua sendo um limite inferior.
- **Rocky Linux e AlmaLinux 8 e 9.** O host é lido por meio do `rpm`. Dados: OSV; só as CVEs que entregaram uma correção são visíveis.
- **Debian e Ubuntu (LTS).** O host é lido de `/var/lib/dpkg` (nada é executado); containers, listas `--packages-from`, SBOMs e `name@version` também funcionam. Dados: OSV, que também lista problemas em aberto (relatados como afetados sem versão de correção).
- **openSUSE Leap 15.x e 16.0, e Tumbleweed.** O host é lido por meio do
  `rpm`, e containers funcionam. Dados: OSV, indexado pelo pacote-*fonte* (a
  biblioteca `libopenssl3` é construída a partir de `openssl-3`): o amivuln lê
  o nome do pacote-fonte no banco de dados do rpm, mas uma lista de pacotes ou
  um SBOM precisa trazê-lo (veja a página Usando o amivuln). Só contam as
  atualizações de segurança (`SUSE-SU`, `openSUSE-SU`), e só as CVEs que
  entregaram uma correção são visíveis. O SUSE Linux Enterprise tem dados
  próprios e ainda não é lido.
- **Gentoo.** O host é lido de `/var/db/pkg` (nada é executado), e containers
  funcionam. Dados: os GLSAs da própria árvore Portage do host
  (`/var/db/repos/gentoo/metadata/glsa`), lidos offline; nada é baixado. Os
  advisories são avaliados por slot, e um intervalo com `slot` só se aplica a um
  pacote naquele slot. Só existem advisories que entregaram uma correção, então
  uma CVE ainda sem correção não é visível. A idade da fonte é o momento da
  última sincronização da árvore; uma árvore ausente, ilegível ou vazia torna o
  resultado incompleto. Para um container ou outra máquina, aponte `[sources.distro] path`
  para um diretório com os arquivos `glsa-*.xml`. O atributo `arch` de um
  advisory não é lido.
- **Alpine 3.x.** O host é lido de `/lib/apk/db/installed`; as mesmas outras entradas do Debian e do Ubuntu. Imagens edge e alpha não têm dados de advisory e são recusadas. Dados: OSV, indexado pelo pacote de origem; só as CVEs que entregaram uma correção são visíveis.
- **Dados de CVE da Red Hat (opcional, desativado por padrão).** O texto de
  `mitigation` que a Red Hat publica por CVE, usado por `--mitigations`. Veja o
  guia para saber o que isso envia e o que não afirma.
- **Runtimes Flatpak.** Lidos do `manifest.json` de cada runtime, avaliados pelo
  NVD para a versão upstream de cada componente, com as listas `patches` e
  `ignored` do próprio builder aplicadas. Lento e com limite de taxa; veja o
  guia.
- **Módulos Go e crates Rust** encontrados em binários, por meio do OSV.

## Planejado

A API Bodhi do Fedora como verificação cruzada, o NVD por CPE como alternativa
e o endoflife.date. O arquivo CSAF VEX da Red Hat (412 MB) foi avaliado e não
escolhido: o arquivo OVAL entrega as CVEs sem correção em 11 MB (ADR-0014).

## Particularidades do Arch

O tracker marca um grupo como *Vulnerable* sem versão corrigida para o build
que era o atual quando a entrada foi escrita, e algumas entradas permanecem
assim por anos. O amivuln relata um pacote instalado como afetado apenas quando
ele tem a mesma versão upstream do build registrado (um rebuild dela continua
afetado). Uma versão upstream mais nova é relatada como *não verificada*,
porque a entrada não consegue dizer se ela ainda se aplica. Uma instalação mais
antiga que o build registrado está fora da entrada e não é relatada.
