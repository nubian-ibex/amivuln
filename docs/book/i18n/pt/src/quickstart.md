# Início rápido

```bash
amivuln nginx                          # um pacote instalado
amivuln /usr/sbin/nginx                # o pacote dono de um arquivo
amivuln nginx.service                  # o pacote por trás de uma unit do systemd
amivuln openssl@3.5.1-1 --distro arch  # uma versão, sem ler o host
amivuln --all                          # todos os pacotes instalados
```

## Perguntas sobre o host inteiro

```bash
amivuln cve CVE-2024-6387      # algum pacote instalado é afetado?
amivuln pending                # quais atualizações reduzem mais o risco, as mais arriscadas primeiro
amivuln services               # verifica o pacote por trás de cada serviço em execução
amivuln restart                # quais processos ainda rodam arquivos que uma atualização substituiu
amivuln --packages-from list.txt   # verifica uma lista de pacotes exportada de outro host
```

`cve` sai com código 1 quando um pacote é afetado. Quando os dados da
distribuição não têm registro da CVE, ele diz isso explicitamente: isso não
significa que o host esteja seguro. `pending` agrupa subpacotes construídos a
partir de uma mesma fonte em uma só atualização e ordena por achados
explorados (KEV), severidade e EPSS. `restart` lê o `/proc` (rode como root
para ver todos os processos; a saída informa quantos não pôde inspecionar) e
sai com código 1 quando algo precisa ser reiniciado. `services` lista os
serviços do systemd em execução que não vêm de pacote, sem fazer a execução
falhar. Uma verificação do sistema inteiro também imprime uma nota do host de
A a F (veja o ADR-0011 no repositório).

## Leia o resultado

Para cada pacote você recebe o número de achados afetados por severidade,
quantos são sabidamente explorados (CISA KEV), a maior pontuação EPSS e a
versão que os corrige, com o comando que você executaria. O amivuln nunca
executa esse comando.

Os achados que a distribuição não consegue confirmar aparecem à parte como
*não verificados* e não são somados aos afetados.

## Reprovar um build

```bash
amivuln --all --fail-on high           # código 1 em HIGH ou pior
amivuln --all --fail-on kev            # código 1 só para CVEs exploradas
amivuln --all -f sarif > amivuln.sarif # SARIF 2.1.0 para code scanning
amivuln --all -f csv > amivuln.csv     # seguro para planilhas (injeção de fórmulas bloqueada)
```

Códigos de saída: `0` limpo, `1` achados no nível de `--fail-on` ou acima, `2`
incompleto, `3` alvo não resolvido, `64` erro de uso, `70` erro interno. O
código `2` impede que uma queda dos dados de segurança passe por uma
verificação limpa.

## Um passo no GitHub Actions

A [amivuln-action](https://github.com/nubian-ibex/amivuln-action) baixa um
release, verifica o atestado e o checksum e então o executa. Fixe-a em um SHA
de commit completo:

```yaml
permissions:
  contents: read
  attestations: read
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high
```

Os mesmos passos, à mão:

```yaml
- name: Baixar o amivuln
  run: |
    gh release download --repo nubian-ibex/amivuln --pattern 'amivuln-x86_64-unknown-linux-musl.tar.zst'
    gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
    tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
- name: Verificar os pacotes
  run: ./amivuln --all --fail-on high
```

Veja também [Usando o amivuln](using.md) para mais cenários.
