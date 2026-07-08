"""
Specs de segurança contra SSRF para o endpoint POST /downloads.

NÃO altere este arquivo. No estado inicial do STARTER as specs de segurança
FALHAM de propósito (a safe_fetch é ingênua). Você faz elas passarem editando
app/safe_fetch.py. O happy-path (baixar um arquivo pequeno) já passa.

Tudo é stubado — respx intercepta o httpx e o DNS é monkeypatchado. NENHUMA
requisição de rede real acontece.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app import safe_fetch as sf
from app.main import app
from app.safe_fetch import MAX_BYTES, SSRFError, safe_fetch

client = TestClient(app)

# Um IP público qualquer, usado quando queremos que a resolução seja "ok".
PUBLIC_IP = "93.184.216.34"


def _resolves_to(ip: str):
    """Fábrica de fake resolvers: todo host resolve para `ip`."""
    return lambda host: ip


# --------------------------------------------------------------------------- #
# Specs de segurança — DEVEM falhar no estado inicial.
# --------------------------------------------------------------------------- #


@respx.mock
def test_rejeita_http_nao_https(monkeypatch):
    monkeypatch.setattr(sf, "resolve_host", _resolves_to(PUBLIC_IP))
    respx.get("http://example.com/f.pdf").mock(
        return_value=httpx.Response(200, content=b"nope")
    )

    with pytest.raises(SSRFError):
        safe_fetch("http://example.com/f.pdf")


@respx.mock
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254"])
def test_rejeita_host_que_resolve_para_ip_interno(monkeypatch, ip):
    # O host "parece" externo, mas o DNS aponta para um endereço interno.
    monkeypatch.setattr(sf, "resolve_host", _resolves_to(ip))
    respx.get("https://internal.example.com/secret").mock(
        return_value=httpx.Response(200, content=b"leak")
    )

    with pytest.raises(SSRFError):
        safe_fetch("https://internal.example.com/secret")


@respx.mock
def test_rejeita_redirect_para_host_privado(monkeypatch):
    # Primeiro host é público; ele redireciona para os metadados de cloud.
    def fake_resolve(host: str) -> str:
        return "169.254.169.254" if "metadata" in host else PUBLIC_IP

    monkeypatch.setattr(sf, "resolve_host", fake_resolve)

    respx.get("https://safe.example.com/start").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://metadata.evil.test/latest/meta-data"}
        )
    )
    respx.get("https://metadata.evil.test/latest/meta-data").mock(
        return_value=httpx.Response(200, content=b"aws-creds")
    )

    with pytest.raises(SSRFError):
        safe_fetch("https://safe.example.com/start")


@respx.mock
def test_corta_arquivo_grande(monkeypatch):
    monkeypatch.setattr(sf, "resolve_host", _resolves_to(PUBLIC_IP))
    big = b"a" * (MAX_BYTES + 4096)
    respx.get("https://cdn.example.com/big.bin").mock(
        return_value=httpx.Response(200, content=big)
    )

    resp = client.post("/downloads", json={"file_url": "https://cdn.example.com/big.bin"})
    assert resp.status_code in (200, 400)
    if resp.status_code == 200:
        assert resp.json()["bytes"] <= MAX_BYTES


# --------------------------------------------------------------------------- #
# Happy-path — pode passar já no estado inicial.
# --------------------------------------------------------------------------- #


@respx.mock
def test_baixa_arquivo_pequeno_stubado(monkeypatch):
    monkeypatch.setattr(sf, "resolve_host", _resolves_to(PUBLIC_IP))
    body = b"hello world"
    respx.get("https://cdn.example.com/ok.txt").mock(
        return_value=httpx.Response(200, content=body)
    )

    resp = client.post("/downloads", json={"file_url": "https://cdn.example.com/ok.txt"})
    assert resp.status_code == 200
    assert resp.json()["bytes"] == len(body)
