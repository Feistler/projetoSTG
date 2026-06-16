"""Testes da API web (pulam se fastapi/httpx nao estiverem instalados)."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from stg.web.app import app  # noqa: E402

client = TestClient(app)


def test_index_served():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Security Toolkit Gateway" in resp.text


def test_connectors_endpoint_lists_18():
    resp = client.get("/api/connectors")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 18
    assert "nmap" in {c["name"] for c in data}


def test_scope_endpoint():
    resp = client.get("/api/scope")
    assert resp.status_code == 200
    assert "configured" in resp.json()


def test_scan_passive_connector_returns_result():
    # hibp e passivo (dispensa escopo) e sem chave -> resultado sem tocar a rede.
    resp = client.post("/api/scan", json={"connector": "hibp", "target": "a@b.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["connector"] == "hibp"
    assert "id" in body
    assert body["status"] in ("unavailable", "failed", "success")


def test_report_unknown_id_404():
    assert client.get("/api/report/inexistente").status_code == 404
