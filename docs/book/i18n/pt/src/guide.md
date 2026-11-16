# Guia do usuário

## Verificando pacotes

```bash
amivuln nginx                 # pacote instalado, pelo nome
amivuln /usr/sbin/nginx       # o pacote dono deste arquivo
amivuln openssl@3.5.1-1       # uma versão específica, sem ler o host
amivuln pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64   # uma package URL
amivuln --all                 # todos os pacotes instalados
```

`--file PATH`, `--package NAME[@VERSION]` e `--purl PURL` são formas explícitas
dos mesmos alvos e podem ser repetidas. Quando um nome é ambíguo (por exemplo,
várias versões do kernel instaladas), o amivuln falha com o código de saída 3 e
diz qual seletor usar. Ele nunca adivinha.

## Lendo o resultado

O resumo imprime, por pacote, o número de achados afetados por severidade,
quantos estão no catálogo CISA KEV, a maior pontuação EPSS, e a versão corrigida
com o comando que você executaria para aplicá-la. O amivuln nunca executa esse
comando.

Os achados que a distribuição não pôde confirmar são listados à parte como
*unverified* e não são contados junto com os afetados. `--strict` faz com que
eles contem para `--fail-on`.

As últimas linhas listam cada fonte consultada, o seu status (`ok`, `stale`,
`failed`, `skipped`), a sua idade e se o resultado está completo. Uma fonte
obrigatória que falhou deixa o resultado **incompleto**: a saída avisa de forma
bem visível e o código de saída é 2, de modo que uma indisponibilidade nunca
pareça uma verificação limpa.

## Uso em CI

```bash
amivuln --all --fail-on high           # reprova o job em HIGH ou pior
amivuln --all --fail-on kev            # reprova só em CVEs ativamente exploradas
amivuln --all --fail-on-epss 0.5       # reprova em alta probabilidade de exploração
amivuln --all -f json > amivuln.json   # guarda um registro legível por máquina
```

Para verificar uma versão de outra distribuição, por exemplo um pacote Fedora em
um runner baseado em Debian, passe `--distro fedora:44` ou `--distro arch`
junto com `name@version`. Só o ecossistema, o nome do pacote e a versão são
enviados pela rede.

## Offline e cache

As respostas ficam em cache em `$XDG_CACHE_HOME/amivuln/cache.sqlite` (padrão
`~/.cache/amivuln`). Uma resposta mais nova que `cache_ttl` (6 h) é usada sem
consultar a rede; quando a rede falha, uma com até `stale_max_age` (72 h) de
idade é usada e relatada como `stale`. `--offline` nunca toca a rede e falha de
forma fechada (código 2) quando o cache não tem nada utilizável.
`amivuln cache info` e `amivuln cache clear` gerenciam o cache; `--no-cache`
ignora o cache em disco.

## Configuração

`amivuln config init` grava um arquivo padrão comentado; `amivuln config show`
imprime a configuração efetiva e `amivuln config validate` a verifica. Chaves
desconhecidas são rejeitadas, para que erros de digitação não passem em
silêncio.

## Idioma

O texto que uma pessoa lê (a saída summary e detail, `pending`, `cve`,
`restart`, e os erros e avisos comuns) segue o locale: o primeiro entre
`LC_ALL`, `LC_MESSAGES` e `LANG` que estiver definido, como em qualquer
ferramenta de linha de comando. Existem inglês e português do Brasil (`pt`);
qualquer outro valor, incluindo `C`, resulta em inglês. Para uma execução:
`LC_ALL=pt_BR.UTF-8 amivuln --all`.

A saída JSON, SARIF, CSV, Markdown, Prometheus, CycloneDX e OpenVEX permanece em
inglês seja qual for o locale, porque outros programas a leem, e o mesmo vale
para o texto de `--help`, os erros de configuração e as mensagens das
bibliotecas com que a ferramenta é construída. Os nomes de severidade, `KEV` e
`EPSS` não são traduzidos. A tradução não foi revisada por um falante nativo;
uma correção é um pull request em um arquivo de texto (veja CONTRIBUTING).

## O kernel em execução

Vários kernels ficam instalados lado a lado na maioria dos hosts e um está em
execução, então `amivuln kernel-core` falha por ser ambíguo. `amivuln --kernel`
verifica o pacote dono da imagem do kernel que está em execução (a release em
`/proc/sys/kernel/osrelease`), seja qual for o restante instalado:

```text
$ amivuln --kernel
kernel-core 7.2.15-200.fc44 (Fedora 44)  <- --kernel 7.2.15-200.fc44.x86_64
  CRITICAL 0   HIGH 0   MEDIUM 1   LOW 0   KEV 0
  Fixed in: 7.3.3-200.fc44  (dnf upgrade kernel-core)
```

Ele é julgado pelos dados da distribuição como qualquer pacote: uma versão
upstream nunca é comparada com os registros de CVE do próprio kernel, porque o
kernel de uma distribuição carrega correções que o número da versão não mostra.
`--all` continua julgando todos os kernels instalados. Live patches (kpatch,
livepatch) não são conhecidos pelo amivuln: ele relata o que a versão do pacote
diz. Veja a ADR-0015.

## Explicando um achado

`amivuln --explain -f detail` acrescenta, sob cada achado, as frases que dizem
por que ele é relatado:

```text
CVE-2026-111253  UNKNOWN  fix: 5.4.7.0-1.fc44  EPSS 0.00
      why: dnf5 5.4.6.0-1.fc44 is older than 5.4.7.0-1.fc44, the build that fixes this CVE in the distribution's data. Installing 5.4.7.0-1.fc44 or later closes it.
      why: FIRST EPSS puts the chance it is exploited in the next 30 days at 0%, above 3% of scored CVEs.
```

Vem desligado por padrão, vale só para a saída detail (os formatos de máquina
são idênticos com e sem ele) e segue o idioma do locale.

Nenhum modelo de linguagem o escreve. Cada frase é um modelo de texto
preenchido com um campo que a execução já tem (a versão instalada, a versão
corrigida, o estado que os dados da distribuição deram, como o pacote foi
identificado, CISA KEV, EPSS, uma mitigação do fornecedor), então o mesmo achado
sempre gera o mesmo texto e cada frase pode ser rastreada até a sua origem. Nada
é enviado a lugar nenhum. O que ele não faz: não avalia se o código vulnerável é
alcançável neste host e não resume a CVE (a descrição não é armazenada). Uma
correspondência de banner de versão e um pacote embutido no arquivo dizem isso,
porque são evidências mais fracas.

## Mitigações

`amivuln --mitigations` mostra também, para cada CVE que ainda afeta o host, o
que a Red Hat diz que pode ser feito enquanto a correção não está instalada:
desativar um módulo, mudar uma configuração, executar um script. É o texto da
própria Red Hat, lido dos seus dados públicos de segurança
(`access.redhat.com/hydra/rest/securitydata/cve/<id>.json`), e apresentado como
tal:

```text
CVE-2024-6387  HIGH  fix: 1:9.6p1-3.fc40.3
      mitigation (Red Hat, not checked on this host): ... set LoginGraceTime to 0 ...
```

Vem **desligado por padrão** porque envia o id de cada CVE em aberto para
`access.redhat.com`; `--mitigations` o liga para uma execução, e
`[sources.mitigations] enabled = true` para todas. Informar só `url` nessa
tabela não o liga. As respostas são guardadas por uma semana.

- O texto é escrito para os produtos da própria Red Hat. O amivuln não verifica
  se ele se aplica a este host nem se a configuração está em vigor, e a linha
  diz isso.
- A Red Hat preenche o campo na maioria das CVEs para dizer que não há nada a
  fazer ("Mitigation for this issue is either not available or ... criteria").
  Isso é a ausência de mitigação e fica de fora: em um container Debian, 30 de
  94 CVEs tinham uma mitigação real.
- Ela aparece como o objeto `mitigation` de um achado no JSON (somente quando
  existe), como `workaround` no documento CycloneDX e na saída detail.
- Uma consulta que falha é nomeada na fonte `redhat-cve` (e com
  `required = true` o resultado fica incompleto); nunca é lida como "não existe
  mitigação". No máximo 400 CVEs são consultadas por execução.

## Runtimes Flatpak

`amivuln --flatpak` verifica também os componentes dos runtimes Flatpak
instalados (a instalação do sistema e a do usuário; `FLATPAK_SYSTEM_DIR` e
`FLATPAK_USER_DIR` são respeitados). Nada é executado: o `manifest.json` de cada
runtime é lido. Os runtimes construídos sobre o freedesktop-sdk (Platform, Sdk,
GNOME, KDE) listam cada componente com a sua versão upstream, e um bloco `x-cpe`
com o nome do produto no NVD, as CVEs que o build já corrigiu (`patches`) e as
que os seus mantenedores decidiram que não se aplicam (`ignored`).

Não há status de correção de distribuição para esses componentes, então as CVEs
vêm do NVD, consultado com a versão upstream de cada componente, e as
declarações do construtor decidem o resto do jeito que os dados de uma
distribuição fazem: uma CVE corrigida está resolvida e uma ignorada é "not
affected", e nenhuma das duas é um achado. O que sobra não indica versão
corrigida, porque a correção é um runtime mais novo (`flatpak update`). Um
componente é nomeado `runtime/branch/component`.

Saiba o que isto não diz:

- Uma CVE que o build corrigiu mas não listou em `patches` aparece como em
  aberto. O zlib do runtime 25.08 está listado para a CVE-2026-22184, que está em
  uma ferramenta (`untgz`) que o runtime não compila, e o manifesto não diz isso.
- O NVD é lento e limita a taxa: 5 requisições em 30 segundos sem chave de API e
  50 com uma. Uma instalação tem centenas de componentes distintos, então a
  primeira execução leva uma hora ou mais sem chave e vários minutos com uma
  (`[sources.nvd] api_key_file`). As respostas são guardadas por um dia e usadas
  por uma semana quando o NVD não pode ser alcançado, então as execuções
  seguintes são rápidas.
- Um componente para o qual o NVD não pôde responder (uma requisição que falhou,
  um limite de taxa, uma lista cortada) é nomeado no detalhe da fonte, a fonte
  fica `failed`, e com `required = true` o resultado fica incompleto (código 2).
  Nunca é lido como "sem CVEs".
- Runtimes sem `manifest.json` (extensões de locales, drivers GL e codecs) são
  contados em uma única entrada `unresolved`. Os aplicativos em si não são
  lidos: eles empacotam as próprias bibliotecas e não trazem esse manifesto.

## SBOM e VEX

`amivuln --all -f cyclonedx` grava um documento CycloneDX 1.6: cada pacote
instalado é um componente, com a sua purl e como foi identificado
(`amivuln:provenance`), e cada achado é uma vulnerabilidade com a sua análise.
`amivuln --all -f openvex` grava um documento OpenVEX 0.2.0 com uma declaração
por pacote e CVE. Ambos servem para `check`; `pending`, `cve` e `restart` os
recusam.

O estado vem dos dados da própria distribuição:

- afetado, com a versão que o corrige quando uma é publicada: `exploitable` no
  CycloneDX, `affected` no OpenVEX;
- corrigido na versão instalada ou antes dela, o que inclui correções que uma
  distribuição portou de volta (backport): `resolved` e `fixed`;
- declarado como não afetado, pela distribuição ou por um arquivo VEX passado
  com `--vex`: `not_affected` em ambos, com o motivo;
- não verificável (sem declaração da distribuição, ou versões que não podem ser
  comparadas): `in_triage` e `under_investigation`.

Quais deles aparecem depende do que a fonte lista. O `updateinfo` do Fedora e o
Arch Security Tracker listam o que corrigiram, então as CVEs corrigidas aparecem
ali. O OSV é consultado sobre a versão instalada, então em hosts Debian, Ubuntu,
Alpine e Red Hat os documentos listam os problemas em aberto, não os que já
foram encerrados.

As declarações são a avaliação desta ferramenta sobre este host, não uma
atestação da distribuição. Uma execução incompleta é marcada com
`amivuln:complete = false` nos metadados do CycloneDX, e um pacote que o amivuln
não conseguiu resolver é contado em `amivuln:unresolved`; o código de saída é 2
como de costume. A saída é determinística: componentes e declarações são
ordenados por purl, e nada aleatório (nenhum número de série) é acrescentado. Os
testes validam ambos os documentos contra os schemas oficiais.

## Prometheus e o textfile collector do node_exporter

`amivuln --all -f prometheus` grava métricas em texto: `amivuln_findings{severity,kev}`,
`amivuln_unverified_findings`, `amivuln_source_up{source}`,
`amivuln_source_age_seconds{source}`, `amivuln_run_complete` e
`amivuln_last_run_timestamp_seconds`. Os rótulos vêm de vocabulários fixos, então
nenhum nome de pacote, nome de host ou caminho chega ao armazenamento de
métricas. Grave a saída em um arquivo `.prom` no diretório textfile por meio de
um arquivo temporário e de um rename, para que o collector nunca leia um arquivo
parcial.

## Rodando em um timer

`contrib/systemd/amivuln.service` e `amivuln.timer` verificam o host a cada seis
horas e gravam `amivuln.prom` para o textfile collector, por meio de `--output`,
de modo que o arquivo é substituído de forma atômica. O serviço roda como um
usuário dinâmico, sem capabilities, com sistema de arquivos somente leitura e um
filtro de chamadas de sistema; `systemd-analyze security amivuln.service`
relata uma exposição de 1.2.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Ajuste `ExecStart` e `ReadWritePaths` quando o diretório textfile for outro. Os
códigos de saída 1 (política), 2 (incompleto) e 3 (não resolvido) ainda gravam um
arquivo válido, então a unit só falha em um erro de uso ou interno.

## Atrás de um proxy ou de uma CA corporativa

Defina a tabela `[network]` no arquivo de configuração:

```toml
[network]
proxy = "http://proxy.corp.example:3128"   # padrão: HTTPS_PROXY e NO_PROXY
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
user_agent_suffix = "team-sre"
```

`ca_file` acrescenta raízes confiáveis às embutidas (PEM, no máximo 1 MiB).
`user_agent_suffix` é anexado ao `User-Agent` e é o único texto específico do
host que pode sair da máquina, e só quando você o define. A URL de um proxy pode
carregar credenciais; o amivuln nunca a imprime. Para usar um espelho interno,
defina `sources.<name>.url`.

## Para agentes de IA: o servidor MCP

`amivuln mcp` fala o Model Context Protocol por stdio (JSON-RPC 2.0 delimitado
por quebras de linha, revisões do protocolo 2025-06-18, 2025-03-26 e
2024-11-05). Registre-o em um cliente assim:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

As ferramentas são somente leitura e cada uma executa uma linha de comando fixa
com `-f json`; o resultado é o mesmo relatório versionado que a linha de comando
imprime.

- `check_target`: `targets` (1 a 20 nomes de pacote, `name@version` ou URLs `pkg:`) e um `distro` opcional.
- `check_cve`: `id` como `CVE-2024-6387`; verifica todos os pacotes instalados.
- `pending_updates`, `needs_restart` e `list_services`: sem argumentos.

Não há shell, nem entrada de caminho de arquivo, nem como passar opções: um alvo
que começa com `-` ou contém caracteres de controle é recusado. O servidor
atualiza o cache local como qualquer outra execução; passe `--offline` ou
`--no-cache` para `amivuln mcp` para restringir isso. Sempre leia `complete` e
`sources` em um resultado antes de tratar uma lista vazia como limpa.

## Verificando um SBOM

`amivuln --sbom bom.cdx.json --distro fedora:44 --fail-on high` lê um documento
CycloneDX JSON (qualquer 1.x), verifica cada componente cuja purl seja um pacote
`rpm`, `deb` ou `alpm` e deixa o host em paz. Uma purl cujo namespace discorda de
`--distro` é um erro. Componentes que não são pacotes do sistema operacional
(npm, PyPI, Maven e assim por diante) não são descartados em silêncio: aparecem
como entradas `unresolved`, uma por tipo de purl com uma contagem, e a execução
sai com 3. Para reprovar só pelos pacotes do sistema operacional, filtre o SBOM
antes, por exemplo com
`jq '.components |= map(select(.purl // "" | startswith("pkg:rpm/")))'`.

## Redes resilientes

As fontes podem ter espelhos. Uma fonte que falha no endpoint primário é
consultada de novo em cada espelho de `fallback`, na ordem escrita, antes de
contar como falha. Toda chamada que falha é repetida com backoff exponencial e
jitter (`retries`, padrão 2, no máximo 10); um `Retry-After` enviado pelo
servidor é respeitado dentro do orçamento de tentativas. Um endpoint que falha
repetidamente aciona um disjuntor por endpoint e é ignorado pelo restante da
execução (`cooldown`, 30 s por padrão), de modo que um espelho morto não trava a
verificação. Um host lento pode ser desacelerado de propósito com
`min_interval`, que espaça as requisições ao mesmo host (por exemplo
`"100ms"`).

A ordem de fallback é: endpoint primário, depois espelhos, depois o cache,
depois o banco offline instalado (veja a seção sobre o banco offline) e, por
fim, a falha. `sources` em toda saída diz qual deles respondeu, a sua idade e se
o resultado está completo.

## Notificações por webhook

Uma seção `[notify]` envia um resumo compacto depois de uma execução de `check`:
fatos do host, completude, nota, totais, ids dos achados. É opt-in e não leva
nada além do que o relatório JSON já declara.

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"   # qualquer endpoint que aceite um POST
bearer_file = "/etc/amivuln/notify-token"   # opcional; enviado como Authorization: Bearer
on = "violation"                            # violation (padrão) | incomplete | always
```

Uma entrega que falha imprime um aviso e nunca muda o código de saída: a decisão
de política foi tomada a partir da verificação, não da notificação.


## O banco offline

`amivuln db` move dados de advisories entre hosts que alcançam a rede e hosts que
não alcançam. O arquivo é um `tar.zst` com o cache SQLite e um manifesto com o
SHA-256 do banco; `--key` e `--sig` acrescentam uma assinatura minisign sobre o
manifesto.

```bash
amivuln --all -f json            # aquece o cache (precisa da rede uma vez)
amivuln db build --archive db.tar.zst
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst       # verifica e instala para este usuário
amivuln db info db.tar.zst
```

`db pull` instala em `$XDG_DATA_HOME/amivuln/offline` e recusa um arquivo mais
antigo que o instalado (anti-rollback); `--force` anula a recusa. Depois de
instalado, uma execução com `--offline` responde a partir dele e relata essas
fontes como `stale`, de modo que um host isolado da rede produz os mesmos
formatos de relatório, com códigos de saída que ainda respeitam `--fail-on`.
`amivuln db verify` sai com 65 quando um arquivo foi adulterado; um `db pull`
regressivo também sai com 65.

A assinatura deliberadamente não é embutida: gere a chave do projeto com a
ferramenta `minisign` e assine fora do amivuln
(`minisign -S -s key.sec -m manifest.json -x db.tar.zst.minisig`), para que a
chave secreta nunca passe por este binário.

## Arquivos que nenhum pacote possui

Um alvo de caminho que o gerenciador de pacotes não conhece (um binário copiado
para um container, software vendorizado) é identificado pela sua própria
`.note.package` do systemd, quando ele tem uma. O pacote, a versão e o sistema
de empacotamento vêm do arquivo, e o relatório marca o pacote com a proveniência
`embedded_note`. Uma nota de outro sistema de empacotamento que não o do host
(uma nota `deb` em um host RPM) é recusada como não resolvida em vez de
adivinhada, e o arquivo nunca é executado.

## Programas Go e Rust que nada possui

Quando um alvo de caminho não pertence a nenhum pacote e não tem nota de pacote,
o amivuln lê os módulos Go (build information) ou os crates Rust (dados do
cargo-auditable) que o programa declara e consulta o OSV sobre cada versão
exata. Os achados mostram a menor versão corrigida acima da instalada, e
`update_hint` diz que o programa precisa ser recompilado, porque nenhum
gerenciador de pacotes consegue atualizar uma dependência ligada
estaticamente. Arquivos que um pacote possui deliberadamente não são expandidos
desta forma: uma distribuição faz backport de correções para código vendorizado
sem mudar as versões, então as versões dos módulos de um binário que tem dono
produziriam falsos positivos.

O endpoint OSV para esta etapa é `[sources.osv]` (obrigatório por padrão: uma
etapa que falha deixa esses módulos sem julgamento, o que não deve parecer
limpo). A severidade textual vem do advisory quando ele a informa (os advisories
do GitHub informam; as entradas RUSTSEC não e relatam `unknown`).

## A chave minisign do projeto

`contrib/offline-db/amivuln.pub` é a chave pública minisign do projeto. É também
o que o workflow noturno usa para verificar o banco antes de ele ser publicado
na release. A chave privada do projeto vive só nos segredos do repositório
(`MINISIGN_SECRET_KEY` mais `MINISIGN_PASSWORD`) e nunca em uma máquina de
desenvolvedor, de modo que um espelho comprometido não consegue fingir frescor
nem reapresentar um banco antigo contornando o timestamp de anti-rollback.


## Verificando um container

`amivuln --container ID` verifica os pacotes instalados dentro de um container.
O runtime (podman, depois docker) é invocado apenas para exportar o rootfs, o
que nunca executa nada dentro do container. O `os-release` do próprio container
decide o ecossistema, então a distribuição do host nunca vaza para a resposta, e
os pacotes são julgados pela fonte correspondente (OSV para Debian, Ubuntu,
Rocky, `AlmaLinux`, Red Hat Enterprise Linux (UBI incluída); o banco rpm por meio
do `rpm` do host para containers da família Fedora). Os achados são rotulados com
o id do container, por exemplo `web:nginx`.

```bash
amivuln --container web --container db --fail-on high
```

Containers Alpine são julgados pelo OSV (`Alpine:v3.20` para a release 3.20). O
banco instalado nomeia a origem de cada subpacote, e o OSV indexa os advisories
do Alpine pela origem, então `libcrypto3` é consultado como `openssl`. Imagens
edge e alpha não têm release no OSV e são recusadas. As versões seguem a
ordenação do `apk` (`1.0_rc1` antes de `1.0`, `-r1` depois de `-r0`).

## Banners de versão em binários

Quando nada mais identifica um binário (sem dono de pacote, sem nota de pacote,
sem metadados de Go ou Rust), o amivuln procura os banners de versão que um
conjunto selecionado de produtos em C imprime: OpenSSL, curl, zlib, SQLite,
nginx e outros. Uma ocorrência vira um alvo com a versão upstream como
impressa, marcado como `string_heuristic` em todos os formatos.

Este é um sinal de **baixa confiança**: a distribuição pode ter feito backport
de correções sem mudar o banner embutido. O veredito é real, mas o usuário deve
confirmá-lo no changelog da distribuição.

### A sonda de versão em sandbox

Com `exec_version_probe = true` em `[general]`, o amivuln também executa
`<file> --version` para arquivos que nada mais identifica e lê os banners do que
ele imprime. Este é o único lugar em que o amivuln executa um alvo, então vem
desligado por padrão e roda em um sandbox aplicado antes do `exec`:

- sem escrita no sistema de arquivos (Landlock), e leitura limitada aos
  diretórios de bibliotecas do sistema e ao diretório do próprio alvo;
- sem sockets e sem acesso a outros processos (seccomp);
- `no_new_privs`, queda para `nobody` quando iniciado como root, 2 s de tempo de
  CPU, sem crescimento de arquivos, sem core dumps, 64 arquivos abertos;
- 2 s de tempo de relógio e 64 KiB de saída por stream.

Quando o kernel não consegue aplicar o sandbox (sem Landlock, ou uma arquitetura
diferente de x86_64 e aarch64), a execução relata um erro para aquele arquivo.
Ela nunca executa o alvo sem confinamento. O filtro seccomp é uma lista de
negação, não uma lista de permissão: os alvos são binários arbitrários cujas
chamadas de sistema de inicialização não podem ser listadas, e o Landlock já
remove o lado do sistema de arquivos.

## Fallback NVD para produtos sem dono

Os alvos da heurística de strings (produtos sem dados de distribuição) também
são verificados na API NVD 2.0 pelo nome CPE. A tabela de mapeamento de CPE é
selecionada à mão (`nginx` mapeia para `f5:nginx`, `curl` para `haxx:curl`); um
produto que a tabela não cobre é ignorado. A fonte é opcional
(`sources.nvd.required = false` por padrão), então uma falha não deixa o
resultado incompleto. A chave de API opcional eleva o limite de taxa de 5 para
50 requisições por 30 segundos.

```toml
[sources.nvd]
enabled = true
required = false
# api_key_file = "/etc/amivuln/nvd-api-key"
```

Os achados do NVD trazem a severidade CVSS da versão de métrica mais recente
disponível, e o veredito é `affected` sem versão de correção: o NVD é um
catálogo de CVEs, não uma fonte de correções de distribuição.
