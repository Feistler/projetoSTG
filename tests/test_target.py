"""Inferencia de tipo de alvo."""

from stg.core.models import Target, TargetType


def test_infers_ip():
    assert Target.parse("192.168.0.1").type == TargetType.IP


def test_infers_cidr():
    assert Target.parse("10.0.0.0/24").type == TargetType.CIDR


def test_infers_url():
    t = Target.parse("https://app.exemplo.com/login")
    assert t.type == TargetType.URL
    assert t.host == "app.exemplo.com"


def test_infers_domain():
    assert Target.parse("exemplo.com").type == TargetType.DOMAIN


def test_infers_email():
    assert Target.parse("user@exemplo.com").type == TargetType.EMAIL


def test_infers_pcap():
    assert Target.parse("captura.pcap").type == TargetType.PCAP
