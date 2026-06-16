"""Modelos: severidade e agregacao de resultados."""

from stg.core.models import Category, Finding, ScanResult, Severity


def test_severity_ordering():
    assert Severity.CRITICAL.score > Severity.HIGH.score > Severity.INFO.score
    assert max([Severity.LOW, Severity.HIGH, Severity.INFO]) == Severity.HIGH


def _finding(sev: Severity) -> Finding:
    return Finding(
        title="x", severity=sev, connector="nmap", category=Category.RECON, target="t"
    )


def test_severity_counts():
    result = ScanResult(
        connector="nmap",
        category=Category.RECON,
        target="t",
        findings=[_finding(Severity.HIGH), _finding(Severity.HIGH), _finding(Severity.LOW)],
    )
    counts = result.severity_counts()
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert result.highest_severity == Severity.HIGH


def test_finding_has_id():
    f = _finding(Severity.INFO)
    assert f.id and len(f.id) == 12
