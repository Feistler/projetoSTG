<h1 align="center">STG &middot; Security Toolkit Gateway</h1>

<p align="center">
  <em>Orquestrador unificado de ferramentas de seguranca ofensiva e defensiva.</em><br>
  Uma unica interface, um unico modelo de achados, um unico relatorio &mdash; para as 18 ferramentas
  que todo profissional de seguranca usa no dia a dia.
</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="docker" src="https://img.shields.io/badge/docker-kali--rolling-1d63ed">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="tests" src="https://img.shields.io/badge/tests-27%20passing-brightgreen">
  <img alt="status" src="https://img.shields.io/badge/status-MVP-orange">
</p>

---

> ## ⚠️ Aviso legal &middot; Uso etico
> O STG executa varreduras e testes que **so podem ser usados contra sistemas para os quais voce
> tem autorizacao explicita e por escrito**. Para reforcar isso, o proprio toolkit possui um
> **gate de escopo** (`config/authorization.yaml`) que **bloqueia** conectores ativos contra alvos
> fora do escopo, alem de uma **trilha de auditoria** imutavel de cada execucao.
> Usar estas ferramentas sem autorizacao e crime (ex.: Lei 12.737/2012 no Brasil). **A responsabilidade e sua.**

---

## Indice
- [Visao geral](#visao-geral)
- [Arquitetura](#arquitetura)
- [As 6 categorias e os 18 conectores](#as-6-categorias-e-os-18-conectores)
- [Recursos que diferenciam o projeto](#recursos-que-diferenciam-o-projeto)
- [Instalacao](#instalacao)
- [Uso](#uso)
- [Escopo autorizado e auditoria](#escopo-autorizado-e-auditoria)
- [Relatorios](#relatorios)
- [Pipelines](#pipelines)
- [Como estender (novo conector)](#como-estender-novo-conector)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Roadmap](#roadmap)

## Visao geral

A maioria das equipes usa dezenas de ferramentas de seguranca isoladas, cada uma com sua propria
saida, seu proprio formato e seu proprio jeito de operar. O **STG** resolve isso com um **nucleo
modular** onde cada ferramenta vira um **conector** que fala a mesma lingua: todos produzem
**`Findings` normalizados**, que alimentam **um relatorio unico** (Markdown / HTML / JSON).

As ferramentas cobrem o **ciclo completo de seguranca**:

| Visao | Categorias |
|-------|-----------|
| 🔴 **Red Team / Ofensivo** | Reconhecimento, Vulnerabilidades, Web, Senhas |
| 🔵 **Blue Team / Defensivo** | Monitoramento de Rede, SIEM & Endpoint |

## Arquitetura

```
                         ┌──────────────────────────────┐
            CLI  (stg)   │  list · info · scan · pipeline · report · authz
                         └───────────────┬──────────────┘
                                         │
                            ┌────────────▼────────────┐
                            │         Runner          │
                            │  autorizacao → execucao │
                            │       → auditoria       │
                            └─────┬──────────────┬────┘
              authorization.yaml  │              │  audit.jsonl (append-only)
                                  │              │
                    ┌─────────────▼──────────────▼─────────────┐
                    │              Registry (18 conectores)     │
                    └─┬─────────┬─────────┬────────┬─────────┬──┘
          CommandConnector   ApiConnector   ...    (mesma interface: run/parse)
                      │            │
              subprocess seguro   HTTP/API
                      │            │
                      ▼            ▼
              ┌──────────────────────────────┐
              │   Findings normalizados       │ → Reporting (MD · HTML · JSON)
              └──────────────────────────────┘
```

Pontos-chave do design:
- **Contrato unico** (`BaseConnector`): adicionar uma ferramenta = criar uma classe pequena.
- **`CommandConnector`** encapsula subprocess seguro (sem `shell=True`, com timeout).
- **`ApiConnector`** encapsula integracoes HTTP (Shodan, Nessus, Wazuh, Splunk, Falcon...).
- **Degradacao graciosa**: ferramenta ausente vira status `UNAVAILABLE`, nunca um crash.

## As 6 categorias e os 18 conectores

| # | Categoria | Conector | Ferramenta | Tipo | Requer |
|---|-----------|----------|-----------|------|--------|
| 1 | Reconhecimento | `nmap` | Nmap | CLI | binario `nmap` |
| 1 | Reconhecimento | `amass` | Amass | CLI | binario `amass` |
| 1 | Reconhecimento | `shodan` | Shodan | API | `SHODAN_API_KEY` |
| 2 | Vulnerabilidades | `nikto` | Nikto | CLI | binario `nikto` |
| 2 | Vulnerabilidades | `nessus` | Nessus | API | API keys Nessus |
| 2 | Vulnerabilidades | `openvas` | OpenVAS/GVM | API | `python-gvm` + creds |
| 3 | Web | `zap` | OWASP ZAP | API | `ZAP_API_KEY` + daemon |
| 3 | Web | `sqlmap` | SQLmap | CLI | binario `sqlmap` |
| 3 | Web | `burp` | Burp Suite | API | Burp Enterprise/Pro* |
| 4 | Senhas | `hashcat` | Hashcat | CLI | binario `hashcat` |
| 4 | Senhas | `john` | John the Ripper | CLI | binario `john` |
| 4 | Senhas | `hibp` | Have I Been Pwned | API | `HIBP_API_KEY` |
| 5 | Monitoramento | `wireshark` | Wireshark (tshark) | CLI | binario `tshark` |
| 5 | Monitoramento | `suricata` | Suricata | CLI | binario `suricata` |
| 5 | Monitoramento | `snort` | Snort | CLI | binario `snort` + ruleset |
| 6 | SIEM & Endpoint | `wazuh` | Wazuh | API | creds Wazuh API |
| 6 | SIEM & Endpoint | `splunk` | Splunk | API | `SPLUNK_TOKEN` |
| 6 | SIEM & Endpoint | `crowdstrike` | CrowdStrike Falcon | API | creds Falcon |

> \* O Burp Suite **Community nao expoe API**. O conector integra com a REST API do Burp
> **Enterprise/Professional**.

## Recursos que diferenciam o projeto

- 🔒 **Gate de autorizacao** &mdash; conectores ativos sao bloqueados fora do escopo declarado.
- 🧾 **Trilha de auditoria** &mdash; cada execucao (autorizada, bloqueada ou forcada) vira uma linha JSONL imutavel com usuario, host, alvo e comando.
- 🧩 **Conectores plugaveis** &mdash; uma classe por ferramenta, descoberta automatica.
- 📊 **Relatorios consolidados** &mdash; Markdown, HTML (standalone) e JSON a partir do mesmo dado.
- 🔗 **Pipelines declarativos** &mdash; encadeie ferramentas via YAML.
- 🐳 **Tudo em Docker** &mdash; imagem Kali com as ferramentas open source ja instaladas.
- ✅ **Testado** &mdash; suite de testes do nucleo e dos parsers (27 testes).

## Instalacao

### Opcao recomendada: Docker (multiplataforma)

```bash
# 1. Configure segredos e escopo
cp .env.example .env                       # preencha as chaves que for usar
cp config/authorization.example.yaml config/authorization.yaml   # ajuste seu escopo

# 2. Build da imagem (Kali + ferramentas open source). Baixa ~1.5-2 GB.
docker build -t stg-toolkit .

# 3. Use
docker compose run --rm stg list
docker compose run --rm stg scan nmap 192.168.56.10 --report html
```

### Opcao desenvolvimento (Python local)

```bash
pip install -e ".[dev]"     # instala o pacote + ferramentas de teste
pytest                       # roda os 27 testes
stg list
```
> No modo local, os **binarios** (nmap, nikto...) precisam estar instalados no sistema. As
> integracoes por **API** funcionam apenas com as chaves no `.env`.

## Uso

```bash
stg version                              # versao
stg list                                 # lista conectores e disponibilidade
stg info nmap                            # detalhes de um conector

# Varredura individual
stg scan nmap 192.168.56.10 --opt top_ports=2000 --opt service_detection=true
stg scan nikto http://alvo.local --report html --report json
stg scan hibp pessoa@empresa.com         # passivo (OSINT), nao exige escopo
stg scan hashcat hashes.txt --opt mode=0 --opt wordlist=/usr/share/wordlists/rockyou.txt

# Fora do escopo? O STG bloqueia (e audita):
stg scan nmap 8.8.8.8                     # → BLOQUEADO
stg scan nmap 8.8.8.8 --force             # → executa, mas registra na auditoria

# Pipeline declarativo
stg pipeline pipelines/recon.yaml --target empresa.local --report html
```

Opcoes de cada conector vao via `--opt chave=valor` (numeros e `true/false` sao convertidos).

## Escopo autorizado e auditoria

O coracao etico do projeto. Defina seu escopo em `config/authorization.yaml`:

```yaml
allow_local_files: true
scope:
  networks:
    - 192.168.56.0/24
  domains:
    - empresa.local
```

```bash
stg authz init                 # cria um arquivo inicial
stg authz check 192.168.56.10  # → AUTORIZADO
stg authz check 8.8.8.8        # → FORA DO ESCOPO
```

Toda execucao gera um registro em `stg-data/audit.jsonl`:

```json
{"timestamp":"2026-06-16T12:00:00Z","user":"adauam","host":"kali","event":"scan",
 "connector":"nmap","target":"192.168.56.10","authorized":true,"forced":false,"status":"success"}
```

## Relatorios

Use `--report md|html|json` (pode repetir). Os arquivos vao para `stg-data/output/`.
O HTML e **standalone** (CSS embutido, badges de severidade) &mdash; pronto para anexar num laudo.

## Pipelines

```yaml
# pipelines/recon.yaml
name: recon-basico
description: Descoberta de subdominios e portas/servicos.
steps:
  - connector: amass
    options: { passive: true }
  - connector: nmap
    options: { top_ports: 1000 }
```

## Como estender (novo conector)

1. Crie `stg/connectors/<categoria>/minha_ferramenta.py` herdando de `CommandConnector` ou `ApiConnector`.
2. Defina os metadados (`name`, `tool`, `category`, `requires_*`, `target_types`).
3. Implemente `build_command()`/`fetch()` e `parse()` (retornando `Finding`s).
4. Adicione a classe ao `CONNECTORS` do `__init__.py` da categoria. Pronto &mdash; aparece no `stg list`.

```python
class MinhaFerramentaConnector(CommandConnector):
    name = "minha"
    tool = "Minha Ferramenta"
    category = Category.RECON
    requires_binaries = ["minha"]
    target_types = [TargetType.DOMAIN]

    def build_command(self, target, options, workdir):
        return ["minha", "--json", target.value]

    def parse(self, raw, target):
        return [self.make_finding("Algo encontrado", target, Severity.MEDIUM)]
```

## Estrutura do projeto

```
projetoSTG/
├── stg/
│   ├── cli.py                 # interface Typer/Rich
│   ├── core/                  # models, connector, registry, runner, authorization, audit, pipeline
│   ├── connectors/            # 6 categorias × 3 ferramentas
│   ├── reporting/             # reporter + templates (md/html)
│   └── utils/                 # shell seguro, logging
├── config/                    # config + authorization (exemplos)
├── pipelines/                 # pipelines YAML de exemplo
├── tests/                     # 27 testes do nucleo e parsers
├── docs/                      # ARCHITECTURE, ETHICS, CONNECTORS
├── Dockerfile · docker-compose.yml · Makefile
└── pyproject.toml
```

## Roadmap

- [ ] Dashboard web (FastAPI) reaproveitando o mesmo nucleo.
- [ ] Exportacao de relatorio em PDF.
- [ ] Normalizacao de severidade por CVSS quando disponivel.
- [ ] Mais conectores (Subfinder, httpx, trivy, Nuclei).
- [ ] Persistencia de achados (SQLite) para historico e diffs.

## Licenca

[MIT](LICENSE). Software fornecido "como esta", sem garantias. O uso indevido e de inteira
responsabilidade do usuario.
