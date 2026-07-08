"""
safe_fetch — baixa o conteúdo de uma URL informada pelo usuário.

ESTADO INICIAL: INGÊNUO. Segue qualquer URL, qualquer esquema, qualquer host,
qualquer número de redirects, sem limite de tamanho. Isso é vulnerável a SSRF
(Server-Side Request Forgery).

Seu trabalho é blindar esta função até os testes de segurança em
tests/test_ssrf.py passarem. NÃO altere os testes.
"""

from __future__ import annotations

import ipaddress
import socket

import httpx

# Limites (o teste espera que o corte de tamanho seja respeitado).
MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 2


class SSRFError(ValueError):
    """URL rejeitada por política de segurança (SSRF)."""


def resolve_host(host: str) -> str:
    """
    Resolve um hostname para um endereço IP (string).

    Isolado numa função para que os testes possam monkeypatchar a resolução
    de DNS e simular um host malicioso apontando para um IP interno, sem rede
    real. NÃO remova nem renomeie esta função.
    """
    return socket.gethostbyname(host)


def is_blocked_ip(ip: str) -> bool:
    """
    TODO(aluno): retorne True se `ip` for um endereço que NÃO deve ser acessado
    a partir do servidor. Bloqueie, no mínimo:

      - loopback            127.0.0.0/8   e IPv6 ::1
      - privados            10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
      - link-local          169.254.0.0/16  (inclui 169.254.169.254, metadados de cloud!)
      - IPv6 unique-local    fc00::/7
      - IPv6 link-local      fe80::/10

    Dica: `ipaddress.ip_address(ip)` expõe `.is_private`, `.is_loopback`,
    `.is_link_local`, `.is_reserved`, `.is_unspecified`. Considere usá-los.

    No estado inicial nada é bloqueado — por isso os testes de segurança falham.
    """
    # INGÊNUO: não bloqueia nada.
    _ = ipaddress.ip_address  # mantém o import à mão para você
    return False


def _check_url_allowed(url: str) -> None:
    """
    TODO(aluno): valide `url` ANTES de qualquer requisição de rede.

      1. Só aceite esquema https (rejeite http://, file://, gopher://, ...).
      2. Extraia o host, resolva com resolve_host(host) e rejeite se
         is_blocked_ip(ip) for True.

    Levante SSRFError("mensagem") quando a URL for proibida.

    No estado inicial nada é validado.
    """
    # INGÊNUO: aceita tudo.
    return None


def safe_fetch(url: str) -> bytes:
    """
    Baixa `url` e devolve o corpo em bytes.

    ESTADO INICIAL (inseguro): segue qualquer URL, sem validação, sem limite de
    redirects, sem limite de tamanho.

    Meta (aluno):
      - chamar _check_url_allowed(url) antes de conectar;
      - seguir no máximo MAX_REDIRECTS redirects, REVALIDANDO o host de destino
        a cada salto (um redirect para http://169.254.169.254 deve ser barrado);
      - aplicar TIMEOUT_SECONDS e cortar em MAX_BYTES.
    """
    # INGÊNUO: segue qualquer coisa, sem limites. TODO: blinde isto.
    with httpx.Client(follow_redirects=True, timeout=TIMEOUT_SECONDS) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.content
