# Usando o amivuln

Receitas para os lugares onde o amivuln costuma rodar. Cada uma está completa o
bastante para copiar; o [guia do usuário](https://ibexwall.com/amivuln/guide.html)
explica as opções a fundo e a [referência](https://ibexwall.com/amivuln/reference.html)
lista todas.

Duas coisas valem em qualquer lugar. Leia `complete` e as linhas `source`
antes de confiar em um resultado vazio: o código de saída `2` significa que uma
fonte obrigatória estava indisponível, o que não é o mesmo que limpo. E só o
ecossistema, o nome do pacote e a versão saem da máquina.

## No seu notebook ou estação de trabalho

```bash
amivuln --all                      # nota e totais de todos os pacotes instalados
amivuln pending                    # quais atualizações reduzem mais o risco, as mais arriscadas primeiro
amivuln openssl --format detail    # um pacote, cada achado com a sua correção
amivuln /usr/bin/ssh               # o pacote dono de um arquivo
```

O `pending` é o mais útil num desktop: agrupa subpacotes construídos de uma
mesma fonte, ordena por achados explorados (KEV), severidade e EPSS e imprime o
comando de atualização. O amivuln nunca o executa.

Para uma visão em tela cheia com filtros, compile com a feature `tui`:

```bash
cargo install amivuln --locked --features tui
amivuln tui          # setas ou j/k para mover, K: só KEV, H: só HIGH, q: sair
```

## Quando uma CVE nova vira notícia

```bash
amivuln cve CVE-2024-6387          # código 1 quando um pacote instalado é afetado
amivuln cve CVE-2024-6387 CVE-2025-26465
amivuln restart                    # processos que ainda rodam arquivos que uma atualização substituiu
```

O `cve` responde `affected`, `not affected` ou `unknown`. `unknown` significa
que a distribuição não tem registro da CVE: isso não afirma que o host esteja
seguro. Depois de instalar a atualização, o `restart` lista os processos que
ainda executam o código antigo.

## Em um servidor, agendado

As units em `contrib/systemd` verificam o host a cada seis horas e gravam
métricas para o textfile collector do node_exporter.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Importe `contrib/grafana/amivuln.json` no Grafana para ter o painel. Para um
cron simples que envia o resultado por e-mail só quando algo está errado:

```cron
17 6 * * *  root  amivuln --all --fail-on high -f markdown || mail -s "amivuln: $(hostname)" ops@example.org
```

Para receber uma mensagem em vez de um painel, acrescente um webhook à
configuração:

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"
on = "violation"
```

## Em um pipeline de CI

GitHub Actions, com o release verificado e o code scanning:

```yaml
permissions:
  contents: read
  attestations: read
  security-events: write
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high -f sarif --output amivuln.sarif
  - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
    if: always()
    with:
      sarif_file: amivuln.sarif
```

Fixe actions de terceiros em um SHA de commit completo, como a primeira. GitLab
CI ou qualquer outro runner:

```yaml
amivuln:
  image: fedora:44
  script:
    - curl -sSLO https://github.com/nubian-ibex/amivuln/releases/latest/download/amivuln-x86_64-unknown-linux-musl.tar.zst
    - tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
    - ./amivuln --all --fail-on kev -f json --output amivuln.json
  artifacts:
    when: always
    paths: [amivuln.json]
```

Verifique o download como mostra a [Instalação](installation.md) antes de
confiar nele. Para reprovar um pull request só pelos achados que ele introduziu,
compare com um relatório do branch principal:

```bash
amivuln --all -f json --output baseline.json        # no main, guardado como artefato
amivuln --all --baseline baseline.json --fail-on high   # no pull request
```

## Containers e imagens

Verifique um container pelo id ou nome; o runtime pode ser podman ou docker. O
amivuln lê o banco de pacotes de um sistema de arquivos exportado e nunca
executa nada dentro dele.

```bash
id=$(podman create docker.io/library/alpine:3.18.0 true)
amivuln --container "$id" --fail-on high
podman rm "$id"
```

Containers Alpine, Debian, Ubuntu, Fedora, Rocky, AlmaLinux e Red Hat (UBI) são
julgados pela própria release. Uma imagem Alpine edge ou alpha não tem dados de
advisories e é recusada em vez de ser relatada como limpa. Passe várias opções
`--container` para verificar uma pilha inteira em um só relatório.

## Muitos hosts, ou um host onde você não pode instalar nada

Exporte uma lista do outro host e verifique-a de onde o amivuln roda. Um
`nome@versão` por linha; `--distro` diz a qual release a lista pertence.

```bash
# Fedora, RHEL, Rocky, AlmaLinux (no host de destino)
rpm -qa --qf '%{NAME}@%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n' > host.txt
# Debian e Ubuntu: os advisories usam o nome do pacote-fonte
dpkg-query -W -f '${source:Package}@${Version}\n' > host.txt
# Alpine: os advisories usam o pacote de origem
awk -F: '/^P:/{p=$2} /^V:/{v=$2} /^o:/{o=$2} /^$/{print (o?o:p)"@"v; p="";v="";o=""}' \
  /lib/apk/db/installed > host.txt

amivuln --packages-from host.txt --distro debian:12 --fail-on high
```

Para uma lista de componentes de um build, aponte para um SBOM CycloneDX:

```bash
amivuln --sbom product.cdx.json --distro debian:12
```

## Sem internet no host

Monte o banco de advisories onde há rede, leve um único arquivo e responda a
partir dele, offline.

```bash
amivuln --all -f json > /dev/null                 # aquece o cache uma vez
amivuln db build --archive db.tar.zst
# copie db.tar.zst para o host isolado e então:
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst
amivuln --all --offline --fail-on high
```

Os resultados vindos do banco são marcados como `stale`, com a idade. O projeto
publica um banco assinado por família de distribuição; veja o guia.

## Atrás de proxy ou de uma CA corporativa

```toml
[network]
proxy = "http://proxy.corp.example:3128"
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
```

Ou aponte `sources.<nome>.url` para um espelho interno. Veja o guia.

## Em scripts e painéis

O relatório JSON é um contrato versionado, então o `jq` basta:

```bash
amivuln --all -f json | jq -r '.targets[] | select(.summary.kev > 0) | .package.name'
amivuln --all -f json | jq '[.targets[].findings[]] | group_by(.severity) | map({(.[0].severity): length}) | add'
amivuln --all -f csv > findings.csv        # seguro para planilhas
amivuln --all -f prometheus --output /var/lib/node_exporter/textfile_collector/amivuln.prom
```

## A partir de um assistente de IA

O `amivuln mcp` é um servidor Model Context Protocol somente leitura. Registre-o
uma vez:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

O assistente então pode verificar pacotes, perguntar se uma CVE afeta o host e
listar as atualizações pendentes. Ele não tem shell, não recebe caminhos de
arquivo e não consegue passar opções.

## Arquivos que nenhum pacote possui

Um binário copiado para `/opt`, um programa Go ou um programa Rust de um build:

```bash
amivuln /opt/tool/bin/server          # nota, build info do Go ou dados do cargo-auditable
```

Se o arquivo não declara nada, o amivuln procura os banners de versão de uma
lista curta de produtos em C e marca o resultado como de baixa confiança. Com
`exec_version_probe = true` em `[general]`, ele também executa `--version` no
arquivo dentro de um sandbox Landlock e seccomp, o que vem desligado por padrão.
