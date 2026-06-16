"""Parsers das ferramentas CLI usam fixtures (nao executam binarios)."""

import json

from stg.connectors.recon.nmap import NmapConnector
from stg.connectors.vuln.nikto import NiktoConnector
from stg.core.models import Severity, Target

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.56.10" addrtype="ipv4"/>
    <hostnames><hostname name="srv.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_parses_open_ports_only():
    findings = NmapConnector().parse(NMAP_XML, Target.parse("192.168.56.10"))
    # 22 e 23 abertos; 80 fechado deve ser ignorado.
    assert len(findings) == 2
    ports = {f.metadata["port"] for f in findings}
    assert ports == {"22", "23"}


def test_nmap_elevates_risky_service():
    findings = NmapConnector().parse(NMAP_XML, Target.parse("192.168.56.10"))
    telnet = next(f for f in findings if f.metadata["service"] == "telnet")
    assert telnet.severity == Severity.LOW


def test_nmap_handles_garbage():
    assert NmapConnector().parse("isto nao e xml", Target.parse("10.0.0.1")) == []


def test_nikto_parses_and_elevates():
    raw = json.dumps(
        [
            {
                "host": "exemplo",
                "vulnerabilities": [
                    {"id": "1", "method": "GET", "url": "/admin",
                     "msg": "Default admin credentials found"},
                    {"id": "2", "method": "GET", "url": "/", "msg": "Header X presente"},
                ],
            }
        ]
    )
    findings = NiktoConnector().parse(raw, Target.parse("http://exemplo"))
    assert len(findings) == 2
    elevated = next(f for f in findings if "Default" in f.title)
    assert elevated.severity == Severity.MEDIUM
