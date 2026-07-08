"""FastAPI app — endpoint de download exposto a SSRF (STARTER)."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.safe_fetch import SSRFError, safe_fetch

app = FastAPI(title="SSRF Download Lab")


class DownloadRequest(BaseModel):
    file_url: str


@app.post("/downloads")
def create_download(payload: DownloadRequest) -> dict:
    """
    Recebe {"file_url": "..."} e baixa o conteúdo via safe_fetch.

    A validação anti-SSRF vive em app/safe_fetch.py — é lá que o aluno trabalha.
    Aqui apenas traduzimos SSRFError -> 400.
    """
    try:
        content = safe_fetch(payload.file_url)
    except SSRFError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"url": payload.file_url, "bytes": len(content)}
