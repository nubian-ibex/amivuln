# Política de suporte

## Versões

Antes da 1.0, apenas a última versão recebe correções, de segurança ou não. A
partir da 1.0, a última versão menor recebe correções de segurança, e uma
correção de segurança é portada para a versão menor anterior por 90 dias após
o lançamento de uma nova versão menor.

## Versão mínima suportada do Rust

O MSRV é o `rust-version` em `Cargo.toml` (1.97 hoje) e o job de CI `msrv`
compila com ele a cada mudança. Ele só é elevado em uma versão menor, nunca em
uma versão de patch, e cada elevação é nomeada no changelog.

## O que é um contrato

O contrato é o comando `amivuln`. As crates de biblioteca de que ele é feito
(`amivuln-core`, `-resolve`, `-version`, `-sources`, `-cache`, `-report`,
`-sandbox`) são publicadas apenas porque o binário depende delas. Elas
compartilham o número de versão dele, inclusive na 1.0, e **não** carregam
nenhuma promessa de estabilidade de API, na 1.0 ou depois: uma versão de patch
pode alterar ou remover seus itens públicos. Dependa delas por sua conta e
risco, ou execute o comando e leia o JSON dele.

- **Saída JSON.** Os documentos carregam `schema_version`. Dentro de uma
  versão, campos nunca são removidos, renomeados nem têm o tipo alterado; um
  campo novo ou um novo valor de enum é uma mudança aditiva e sai em uma versão
  menor com uma nota no changelog e no [esquema](json-schema.md) publicado.
  Quebrar o formato significa uma nova `schema_version`. Os documentos golden
  em `tests/golden` fixam a saída exata, inclusive a ordem dos campos, e devem
  continuar validando contra o esquema atual; uma mudança neles fica visível na
  revisão.
- **Códigos de saída.** 0, 1, 2, 3, 64, 65 e 70 e sua precedência são
  estáveis.
- **Configuração.** As chaves não são removidas nem renomeadas dentro de uma
  versão maior; chaves novas têm padrões que mantêm o comportamento de hoje.
- **Linha de comando.** As flags não são removidas nem reaproveitadas dentro de
  uma versão maior. A saída de texto (`summary`, `detail`) é para humanos e
  pode mudar.

### Como o contrato é verificado

Cada promessa tem um teste que falha quando ela é quebrada por acidente:

- todo valor que a ferramenta pode gravar (cada ecossistema, fonte,
  procedência, severidade, estado e a `mitigation` opcional) é validado contra
  os esquemas publicados de `check`, `pending` e `cve`; as listas são `match`es
  exaustivos, então um novo valor de enum deixa de compilar até que o esquema e
  o teste o conheçam;
- os documentos JSON golden fixam a saída exata de `check`;
- a configuração padrão é um arquivo golden, e toda chave opcional que
  `config init` nomeia é carregada de volta (uma chave renomeada ou removida
  falha);
- os códigos de saída são verificados por valor;
- a página de manual e os autocompletes de shell são gerados a partir da linha
  de comando e comparados no CI, então uma flag removida ou renomeada aparece
  como diff.

Acrescentar a um conjunto fechado (um novo ecossistema, uma nova fonte) é uma
mudança aditiva e sai em uma versão menor; o esquema e o changelog a nomeiam.

## Plataformas

Linux em x86_64 e aarch64 (builds estáticos `musl` e `glibc`). macOS e Windows
não são suportados. Quais distribuições são avaliadas, e como, está em
[Fontes de dados](sources.md#distribuições-suportadas).
