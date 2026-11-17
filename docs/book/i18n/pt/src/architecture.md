# Arquitetura

O amivuln é um workspace Cargo. O binário `amivuln` apenas orquestra; as
regras de domínio não fazem I/O.

## Pipeline

1. **Alvo.** O que o usuário perguntou: um nome de pacote, um caminho de
   arquivo, uma unidade `.service`, `name@version` ou um purl
   (`amivuln-resolve`).
2. **Identidade.** O pacote instalado, lido do gerenciador de pacotes
   (`rpm`, `pacman`) por um executor de subprocessos limitado e com lista de
   permissão, do banco de pacotes exportado de um container (dpkg, apk ou
   rpm), de uma lista ou de um SBOM, ou dos metadados do próprio arquivo
   (nota de pacote, informações de build do Go, `cargo-auditable`).
3. **Dados da distribuição.** Os dados de advisories da própria distribuição,
   obtidos por um cliente HTTP ciente do cache (`amivuln-sources`,
   `amivuln-cache`).
4. **Correspondência (matching).** O status da distribuição decide, nunca um
   intervalo de versões do upstream. `Fixed(v)` com versão instalada igual ou
   superior a `v` está corrigido; uma versão mais antiga é afetada e informa a
   versão que a corrige (`amivuln-core`).
5. **Enriquecimento.** CISA KEV e FIRST EPSS.
6. **Política.** `--fail-on`, `--fail-on-epss`, `--strict` e a precedência dos
   códigos de saída 70, 64, 2, 3, 1, 0.
7. **Relatório.** `summary`, `detail`, JSON, SARIF, Markdown, CSV e Prometheus (`amivuln-report`).

## Crates

- `amivuln`: linha de comando, configuração e orquestração.
- `amivuln-core`: tipos de domínio, regras de correspondência, política,
  códigos de saída e os traits para o mundo externo.
- `amivuln-resolve`: resolução de alvos e o executor de processos do sistema.
- `amivuln-version`: comparação de versões RPM, pacman, Debian, apk e
  semânticas, verificada contra `rpm`, `vercmp`, `dpkg` e `apk version -t`.
- `amivuln-sandbox`: o sandbox Landlock e seccomp da sonda de versão
  opcional, a única crate com código `unsafe`.
- `amivuln-sources`: parsers do Arch Security Tracker, do `updateinfo` do
  Fedora, do OSV, do NVD, do CISA KEV e do FIRST EPSS, e o cliente HTTP
  limitado.
- `amivuln-cache`: cache HTTP em SQLite com revalidação por ETag e
  classificação em fresco/obsoleto/expirado.
- `amivuln-report`: formatadores de saída.

Todas as crates são publicadas no crates.io porque o binário depende delas.
As crates de biblioteca compartilham a versão do binário e não carregam
nenhuma promessa de estabilidade de API, na 1.0 ou depois: o contrato é o
comando (veja a política de suporte).

## Invariantes

- O status da distribuição substitui a comparação de versões do upstream.
- Um achado sem declaração da distribuição é *não verificado*, listado à
  parte e nunca contado como afetado.
- Uma fonte obrigatória que falha torna o resultado incompleto (código de
  saída 2). Dados em cache obsoletos dentro de `stale_max_age` são usados e
  relatados como `stale`.
- Toda leitura de arquivo, resposta HTTP e saída de subprocesso tem tamanho
  limitado, todo subprocesso tem timeout e um caminho absoluto em lista de
  permissão, e nenhum shell é envolvido.
- Texto vindo de fora do processo é sanitizado antes de chegar a um terminal.
- Nenhum campo que identifique o host existe na saída nem nas requisições.
