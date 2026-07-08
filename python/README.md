# Lab: Secure a Download Endpoint Against SSRF — variante Python/FastAPI

STARTER **incompleto**. O endpoint `POST /downloads` recebe `{"file_url": "..."}`
e baixa o conteúdo via `safe_fetch(url)`. No estado inicial `safe_fetch` é
**ingênua**: segue qualquer URL, qualquer esquema, qualquer host, qualquer
redirect, sem limite de tamanho — ou seja, vulnerável a **SSRF**.

Seu trabalho é blindar `app/safe_fetch.py` até os testes de segurança passarem.

> Este é o starter **Python/FastAPI**. O mesmo lab também tem as variantes
> `rails/` e `typescript/`.
>
> Lab: https://darelabs.tech/labs/secure-a-download-endpoint-against-ssrf

## Setup

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate

pip install -r requirements.txt
pytest
```

No estado inicial as specs de segurança **falham** e o happy-path passa. Isso é
esperado — é o seu ponto de partida.

## Critério de conclusão

Faça `pytest` ficar verde implementando, em `app/safe_fetch.py`:

- **Só https** — rejeite `http://`, `file://`, etc.
- **Bloquear IP interno** (`is_blocked_ip`) — resolva o host e recuse:
  - loopback `127.0.0.0/8`, IPv6 `::1`
  - privados `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - link-local `169.254.0.0/16` (**inclui `169.254.169.254`**, metadados de cloud)
  - IPv6 `fc00::/7` (unique-local) e `fe80::/10` (link-local)
- **Redirects** — no máximo 2, **revalidando o host de destino** a cada salto
  (um redirect para um host interno deve ser barrado).
- **Limite de tamanho + timeout** — corte em `MAX_BYTES`, respeite `TIMEOUT_SECONDS`.

Os `TODO(aluno)` no código marcam exatamente onde trabalhar. Não altere os testes.

## Estrutura

```
app/
  main.py        FastAPI + rota POST /downloads
  safe_fetch.py  INGÊNUO — você endurece aqui (TODOs)
tests/
  test_ssrf.py   specs (não editar)
```
