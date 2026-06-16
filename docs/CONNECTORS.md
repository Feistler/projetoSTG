# Guia de conectores

## Estado de cada integracao
"Real" = parser/integracao implementados e exercitados. "Requer infra" = implementado, mas
depende de servico/credencial/licenca externa para produzir dados.

| Conector | Tipo | Estado | Observacao |
|----------|------|--------|-----------|
| `nmap` | CLI | Real | Parser XML completo (portas/servicos). |
| `amass` | CLI | Real | Parser de subdominios. |
| `shodan` | API | Real | Requer `SHODAN_API_KEY`. |
| `nikto` | CLI | Real | Parser JSON. |
| `nessus` | API | Requer infra | Le o scan mais recente via REST. |
| `openvas` | API | Requer infra | GMP via `python-gvm`. |
| `zap` | API | Real | Le alertas; com `active:true` faz spider+ascan. |
| `sqlmap` | CLI | Real | Detecta parametros injetaveis e DBMS. |
| `burp` | API | Requer infra | Burp Enterprise/Pro (Community nao tem API). |
| `hashcat` | CLI | Real | Le hashes quebrados do outfile. |
| `john` | CLI | Real | Roda o ataque e usa `--show`. |
| `hibp` | API | Real | Requer `HIBP_API_KEY`. |
| `wireshark` | CLI | Real | `tshark`: detecta trafego em texto claro. |
| `suricata` | CLI | Real | Le alertas do `eve.json`. |
| `snort` | CLI | Requer infra | Precisa de ruleset (`--opt config=...`). |
| `wazuh` | API | Requer infra | Reporta agentes inativos. |
| `splunk` | API | Requer infra | Executa busca SPL via REST. |
| `crowdstrike` | API | Requer infra | Importa deteccoes (Detects API, OAuth2). |

## Opcoes uteis (`--opt chave=valor`)

### nmap
- `top_ports` (int), `ports` (ex.: `1-1000`), `service_detection` (bool), `os_detection` (bool),
  `scripts` (ex.: `vuln`), `timing` (0-5).

### nikto
- `port`, `ssl` (bool), `tuning`, `maxtime`.

### sqlmap
- `data` (POST), `cookie`, `level` (1-5), `risk` (1-3), `dbms`, `dbs` (bool).

### zap
- `active` (bool), `max_wait` (segundos).

### hashcat
- `mode` (tipo de hash, ex.: 0=MD5), `attack` (0=dict), `wordlist`.

### john
- `wordlist`, `format` (ex.: `raw-md5`).

### suricata / snort
- `config` (caminho do .yaml/.conf), `rules` (suricata).

## Como adicionar um conector
Ver a secao ["Como estender"](../README.md#como-estender-novo-conector) do README. Resumo:
crie a classe na pasta da categoria, implemente `build_command`/`fetch` + `parse`, e registre no
`CONNECTORS` do `__init__.py`.
