# =============================================================================
# STG - imagem baseada em Kali Rolling com as ferramentas open source pre-
# instaladas. Ferramentas comerciais (Nessus, Burp, Splunk, CrowdStrike) sao
# integradas via API e nao precisam estar na imagem.
# =============================================================================
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Ferramentas open source das categorias 1-5.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nmap amass nikto sqlmap \
        hashcat john \
        tshark suricata snort \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/stg
COPY pyproject.toml README.md ./
COPY stg ./stg
RUN pip3 install --no-cache-dir --break-system-packages .

# O nmap do Kali tem file-capabilities (cap_net_admin=eip). Como NET_ADMIN nao
# faz parte do conjunto padrao do Docker, o exec falharia com "Operation not
# permitted". Removemos as caps do binario: o container roda como root e usa o
# NET_RAW que ja vem por padrao (suficiente para SYN scan).
RUN setcap -r /usr/lib/nmap/nmap || true

# Toolkit de seguranca roda como root: nmap (raw sockets), tshark, suricata e
# snort precisam de privilegios de rede. Para endurecer, use --cap-drop no run.
RUN mkdir -p /data
WORKDIR /data

ENTRYPOINT ["stg"]
CMD ["--help"]
