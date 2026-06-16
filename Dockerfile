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

# Usuario nao-root para execucao.
RUN useradd -m -u 1000 stg && mkdir -p /data && chown -R stg:stg /opt/stg /data
USER stg
WORKDIR /data

ENTRYPOINT ["stg"]
CMD ["--help"]
