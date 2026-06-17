"""Geracao de relatorios consolidados."""

import json

from stg.core.models import Category, Finding, ScanResult, Severity
from stg.reporting import generate_report


def _sample_results() -> list[ScanResult]:
    return [
        ScanResult(
            connector="nmap",
            category=Category.RECON,
            target="192.168.56.10",
            findings=[
                Finding(
                    title="Porta aberta 23/tcp - telnet",
                    severity=Severity.LOW,
                    connector="nmap",
                    category=Category.RECON,
                    target="192.168.56.10",
                ),
                Finding(
                    title="SQL Injection",
                    severity=Severity.HIGH,
                    connector="nmap",
                    category=Category.RECON,
                    target="192.168.56.10",
                ),
            ],
        )
    ]


def test_generates_all_formats(tmp_path):
    paths = generate_report(_sample_results(), tmp_path, formats=("md", "html", "json"))
    assert set(paths) == {"md", "html", "json"}
    for path in paths.values():
        assert path.exists() and path.stat().st_size > 0


def test_json_is_valid(tmp_path):
    paths = generate_report(_sample_results(), tmp_path, formats=("json",))
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data[0]["connector"] == "nmap"
    assert len(data[0]["findings"]) == 2


def test_html_contains_branding(tmp_path):
    paths = generate_report(_sample_results(), tmp_path, formats=("html",))
    html = paths["html"].read_text(encoding="utf-8")
    assert "Fantase" in html
    assert "SQL Injection" in html
