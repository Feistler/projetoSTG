"""Conteudo didatico do painel: metodologia por fase e dicas por ferramenta.

Mantido junto da camada web por ser conteudo de apresentacao/ensino. As chaves
de CATEGORY_GUIDE batem com os valores de stg.core.models.Category.
"""

from __future__ import annotations

CATEGORY_GUIDE: dict[str, dict[str, object]] = {
    "reconhecimento": {
        "ordem": 1,
        "titulo": "Reconhecimento & Varredura",
        "time": "Red Team",
        "resumo": "Mapear a superficie de ataque antes de tocar em qualquer coisa.",
        "objetivo": "Descobrir hosts vivos, portas/servicos expostos e ativos (subdominios, dispositivos na internet).",
        "como_ler": "Cada porta aberta e uma possivel via de entrada. Anote servicos sensiveis e versoes antigas para a proxima fase.",
    },
    "vulnerabilidades": {
        "ordem": 2,
        "titulo": "Avaliacao de Vulnerabilidades",
        "time": "Red Team",
        "resumo": "Cruzar o que foi descoberto com falhas conhecidas (CVEs e configuracoes inseguras).",
        "objetivo": "Identificar versoes vulneraveis, arquivos perigosos e misconfigs nos servicos mapeados.",
        "como_ler": "Priorize por severidade. HIGH/CRITICAL com CVE conhecido sao os candidatos a exploracao.",
    },
    "web": {
        "ordem": 3,
        "titulo": "Testes de Seguranca Web",
        "time": "Red Team",
        "resumo": "Testar aplicacoes web a fundo - e onde vive o OWASP Top 10.",
        "objetivo": "Encontrar injecoes (SQLi), falhas de autenticacao, headers ausentes e logica quebrada.",
        "como_ler": "Um parametro injetavel (SQLi) e critico: pode dar acesso ao banco. Headers ausentes sao higiene.",
    },
    "senhas": {
        "ordem": 4,
        "titulo": "Palavras-passe & Autenticacao",
        "time": "Red Team",
        "resumo": "Avaliar a forca das credenciais - o elo mais explorado.",
        "objetivo": "Auditar hashes (quebra por dicionario) e checar se contas aparecem em vazamentos conhecidos.",
        "como_ler": "Hash que cai em segundos = senha fraca. E-mail em vazamento = risco de reuso de senha.",
    },
    "monitoramento-rede": {
        "ordem": 5,
        "titulo": "Monitorizacao de Rede",
        "time": "Blue Team",
        "resumo": "Lado defensivo: observar o trafego e detectar intrusoes.",
        "objetivo": "Analisar capturas (PCAP), achar trafego em texto claro e disparar regras de IDS (Snort/Suricata).",
        "como_ler": "Credenciais em texto claro e um achado serio. Alertas de IDS indicam padroes maliciosos conhecidos.",
    },
    "siem-endpoint": {
        "ordem": 6,
        "titulo": "SIEM & Protecao de Endpoints",
        "time": "Blue Team",
        "resumo": "A sala de controle do SOC: centralizar logs e responder em endpoints.",
        "objetivo": "Correlacionar eventos (SIEM) e importar deteccoes de endpoint (EDR) para visibilidade total.",
        "como_ler": "Agentes inativos sao pontos cegos. Deteccoes de endpoint apontam atividade suspeita ja em curso.",
    },
}

TOOL_TIPS: dict[str, str] = {
    "nmap": "Portas abertas = servicos expostos. Foque em servicos sensiveis (telnet, smb, rdp) e versoes antigas.",
    "amass": "Cada subdominio e uma nova porta de entrada potencial. Amplia a superficie alem do dominio principal.",
    "shodan": "Mostra como o IP aparece para o mundo (sem tocar no alvo). Otimo para achar CVEs e servicos esquecidos expostos.",
    "nikto": "Aponta arquivos perigosos, servidor desatualizado e headers ausentes. Bom ponto de partida em web.",
    "nessus": "Scanner comercial maduro: importa o scan mais recente. Priorize pela severidade do plugin.",
    "openvas": "Alternativa open source ao Nessus (GVM). Le os resultados ja produzidos pelo scanner.",
    "zap": "Proxy de seguranca do OWASP. Com 'active=true' faz spider + active scan na aplicacao.",
    "sqlmap": "Confirma e explora SQL Injection. Um parametro injetavel costuma ser critico.",
    "burp": "Padrao de mercado em web. A versao Community nao tem API; integra via Enterprise/Pro.",
    "hashcat": "Quebra hashes usando GPU. Auditoria: hash que cai rapido = politica de senha fraca.",
    "john": "Classico de auditoria de senhas. Mostra quais contas usam senhas quebraveis.",
    "hibp": "Consulta passiva: diz se um e-mail ja apareceu em vazamentos publicos conhecidos.",
    "wireshark": "Le PCAP e destaca trafego sensivel (FTP/Telnet/HTTP) - credenciais em texto claro.",
    "suricata": "IDS/IPS moderno: aplica regras sobre o PCAP e normaliza os alertas (eve.json).",
    "snort": "IDS veterano: detecta padroes maliciosos via ruleset. Precisa de um snort.conf.",
    "splunk": "Plataforma de logs: roda uma busca SPL e traz os eventos relevantes.",
    "wazuh": "SIEM open source: aqui, reporta agentes inativos - os pontos cegos do monitoramento.",
    "crowdstrike": "EDR de mercado (Falcon): importa as deteccoes de endpoint mais recentes.",
}
