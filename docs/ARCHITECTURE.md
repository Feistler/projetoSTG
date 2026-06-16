# Arquitetura

## Principio central
Toda ferramenta integrada e um **conector** que implementa o mesmo contrato. Isso permite que o
runner, os pipelines e os relatorios tratem qualquer ferramenta de forma identica, sem `if/else`
espalhado pelo codigo.

## Camadas

```
CLI (Typer)  ->  Runner  ->  Registry  ->  Connectors  ->  Findings  ->  Reporting
                   |            |
              Authorization   (descoberta)
                   |
                 Audit
```

### 1. Models (`stg/core/models.py`)
- `Severity` &mdash; enum ordenavel por gravidade (INFO < LOW < MEDIUM < HIGH < CRITICAL).
  Como herda de `str`, **todos** os operadores de comparacao sao sobrescritos para usar o `score`,
  e nao a ordem alfabetica.
- `Target` &mdash; valor + tipo inferido (`Target.parse`): IP, CIDR, dominio, URL, e-mail, arquivo, PCAP.
- `Finding` &mdash; achado normalizado (titulo, severidade, alvo, evidencia, metadados, referencias).
- `ScanResult` &mdash; resultado de uma execucao (status, findings, comando, duracao, erro).

### 2. Connector (`stg/core/connector.py`)
- `BaseConnector` &mdash; template method `run()`: verifica disponibilidade → valida alvo →
  executa → faz parse → encapsula tudo num `ScanResult` (erros viram status, nunca exceptions soltas).
- `CommandConnector` &mdash; ferramentas CLI; executa via subprocess seguro com `workdir` temporario.
- `ApiConnector` &mdash; servicos HTTP; subclasse implementa `fetch()`.

### 3. Registry (`stg/core/registry.py`)
Indexa todos os conectores de `stg/connectors/__init__.py::ALL_CONNECTORS`. Import tardio evita
ciclos. Permite lookup por nome e agrupamento por categoria.

### 4. Authorization (`stg/core/authorization.py`)
Carrega o escopo (`config/authorization.yaml`) e responde `is_authorized(target)`:
- IP/CIDR → precisa ser sub-rede de uma rede autorizada.
- dominio/host/URL/e-mail → o host precisa casar com (ou ser subdominio de) um dominio autorizado.
- arquivo/PCAP → permitido por padrao (recurso local).

### 5. Audit (`stg/core/audit.py`)
Trilha **append-only** em JSONL. Cada `scan` e `blocked` registra timestamp, usuario, host, alvo,
se foi autorizado/forcado e o comando.

### 6. Runner (`stg/core/runner.py`)
O unico caminho de execucao: resolve o conector, checa autorizacao (conectores `passive` pulam o
gate), audita e delega para `connector.run()`.

### 7. Reporting (`stg/reporting/`)
Agrega `ScanResult`s em um contexto e renderiza via Jinja2 (`report.md.j2`, `report.html.j2`) ou
serializa em JSON (`model_dump`).

## Decisoes de design
- **Sem `shell=True`** em lugar nenhum: comandos sao listas de argumentos.
- **Falha graciosa**: ferramenta ausente → `UNAVAILABLE`; alvo invalido → `SKIPPED`; erro → `FAILED`.
- **Segredos fora do codigo**: `.env` / variaveis de ambiente, nunca commitados.
- **Extensibilidade**: novo conector = nova classe + 1 linha no `CONNECTORS` da categoria.
