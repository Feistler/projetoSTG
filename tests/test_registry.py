"""Registro de conectores: descoberta e integridade."""

from stg.core.models import Category
from stg.core.registry import get_registry


def test_eighteen_connectors():
    assert len(get_registry().names()) == 18


def test_three_per_category():
    grouped = get_registry().by_category()
    for category in Category:
        assert len(grouped[category]) == 3, f"{category} deveria ter 3 conectores"


def test_names_are_unique_and_present():
    names = get_registry().names()
    assert len(names) == len(set(names))
    for expected in ("nmap", "nikto", "sqlmap", "hashcat", "suricata", "wazuh"):
        assert expected in names


def test_build_instance():
    connector = get_registry().build("nmap", settings=_settings())
    assert connector.tool == "Nmap"


def _settings():
    from stg.core.config import Settings

    return Settings()
