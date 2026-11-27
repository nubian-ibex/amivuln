# Referência

## Comandos

- `amivuln [OPTIONS] TARGET...` é um atalho para `amivuln check`.
- `amivuln check [TARGET...] [--all]`
- `amivuln cve CVE-ID...`: este host é afetado? Código de saída 1 quando é.
- `amivuln pending`: as atualizações que mais reduzem o risco, em ordem.
- `amivuln services`: verifica o pacote por trás de cada serviço systemd em execução.
- `amivuln restart`: processos que ainda executam arquivos que uma atualização substituiu. Código de saída 1 quando é preciso reiniciar.
- `amivuln config show | init [--path FILE] | validate`
- `amivuln cache info | clear`
- `amivuln completions bash|zsh|fish|elvish|powershell`
- `amivuln db build|pull|verify|info`: o banco de advisories offline (veja o guia do usuário)
- `amivuln tui`: uma visão em tela cheia com filtros (compile com `--features tui`)
- `amivuln mcp`: um servidor Model Context Protocol somente leitura em stdio (veja o guia do usuário)
- `amivuln version [--json]`

## Opções

- `-f, --format`: `summary`, `detail`, `json`, `sarif`, `markdown`, `csv`, `prometheus`, `cyclonedx` ou `openvex`
- `[network] retries = 2`: tentativas por chamada que falha; `cooldown = "30s"`: pausa do disjuntor; `min_interval`: espaçamento opcional por host
- `--output FILE`: grava o resultado em FILE em vez de stdout; o arquivo é substituído de forma atômica por meio de um rename
- `--fail-on`: `none`, `low`, `medium`, `high`, `critical` ou `kev`
- `--fail-on-epss SCORE`: sai com 1 quando um achado afetado atinge esta pontuação EPSS
- `--strict`: achados não verificados contam para `--fail-on`
- `--offline`, `--no-cache`: comportamento de rede e de cache
- `--config FILE`: usa somente este arquivo de configuração
- `--color auto|always|never`: `NO_COLOR` é respeitado
- `--distro fedora:NN|arch|debian:NN|ubuntu:NN.NN|alpine:N.NN|opensuse:NN.N|opensuse:tumbleweed|gentoo|rhel:N|rocky:N|alma:N`: trata o host como esta distribuição
- `--baseline FILE`: um relatório `-f json` anterior; só os achados ausentes dele violam `--fail-on`
- `--pid PID`: verifica o executável de um processo em execução (repetível); um processo que não existe mais, que não pode ser lido ou cujo executável foi substituído em disco é relatado como não resolvido
- `--sbom FILE`: verifica os pacotes do sistema operacional de um SBOM CycloneDX JSON (purls rpm, deb, apk e alpm); os demais componentes são listados como não resolvidos, uma entrada por tipo de purl
- `--vex FILE`: um documento `OpenVEX`; uma declaração `not_affected` substitui o veredito e mostra o autor e a justificativa
- `--kernel`: verifica também o kernel que está em execução, seja qual for o restante instalado (veja o guia)
- `--explain`: sob cada achado da saída detail, diz em palavras simples por que ele é relatado (modelos de texto sobre os dados da própria execução; sem modelo de linguagem, nada é enviado)
- `--mitigations`: procura também a mitigação que a Red Hat publica para cada CVE afetada (envia os ids das CVEs para access.redhat.com)
- `--flatpak`: verifica também os componentes dos runtimes Flatpak instalados (veja o guia sobre o que isso custa e o que não consegue dizer)
- `--container ID`: verifica os pacotes de um container podman ou docker (repetível); imagens Alpine, Debian, Ubuntu, Fedora, openSUSE, Gentoo, Rocky, AlmaLinux e Red Hat (UBI) são lidas de um sistema de arquivos raiz exportado e nada é executado dentro delas
- `--packages-from FILE`: verifica os pacotes listados em FILE (um `name@version` ou purl por linha) em vez dos instalados
- `ignore_file` (configuração): achados aceitos; entradas expiradas são erros
- `-q, --quiet`: somente erros

`AMIVULN_FORMAT`, `AMIVULN_FAIL_ON`, `AMIVULN_OFFLINE`, `AMIVULN_CONFIG` e
`AMIVULN_COLOR` definem as opções correspondentes.

## Códigos de saída

- 0: concluído, nada em `--fail-on` ou acima
- 1: concluído, achados em `--fail-on` ou acima
- 2: incompleto: uma fonte obrigatória estava indisponível
- 3: um alvo não pôde ser resolvido
- 64: erro de uso ou de configuração
- 70: erro interno

Quando vários se aplicam, a precedência é 70, 64, 2, 3, 1, 0.

## Saída JSON (versão 1 do schema)

```json
{
  "schema_version": 1,
  "tool": {"name": "amivuln", "version": "0.1.0"},
  "generated_at": "2026-11-08T12:00:00Z",
  "host": {"os_id": "fedora", "os_version": "44", "arch": "x86_64"},
  "complete": true,
  "sources": [{"id": "fedora-updateinfo", "status": "ok", "age_s": 0, "required": true}],
  "targets": [{
    "input": "nginx",
    "package": {"name": "nginx", "version": "1:1.26.2-1.fc44", "arch": "x86_64",
                "ecosystem": "fedora", "purl": "pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64&epoch=1",
                "provenance": "package_db"},
    "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0, "epss_max": 0.02, "unverified": 0},
    "findings": [{"id": "CVE-2026-0001", "severity": "high",
                  "distro_status": {"state": "affected", "fixed_in": "1:1.26.3-1.fc44"},
                  "kev": null, "epss": {"score": 0.02, "percentile": 0.6, "date": "2026-11-07"}}],
    "unverified": []
  }],
  "unresolved": []
}
```

O JSON Schema é publicado em [schema/v1.json](https://ibexwall.com/amivuln/schema/v1.json) e é conferido contra a saída real no CI. Achados e achados não verificados são arrays separados. O bloco host nunca
contém nome de host, endereço ou usuário. Acrescentar campos opcionais não muda
`schema_version`; remover um campo ou mudar o seu tipo muda.

## Arquivo de configuração

```toml
schema_version = 1
[general]
offline = false
cache_ttl = "6h"
stale_max_age = "72h"
timeout = "10s"
exec_version_probe = false
[output]
format = "summary"
color = "auto"
[policy]
fail_on = "none"
fail_on_incomplete = true
strict = false
[sources.distro]
enabled = true
required = true
# url = "https://mirror.example/fedora/linux/updates"
[sources.kev]
enabled = true
[sources.epss]
enabled = true
```
