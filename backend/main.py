"""
Sentinela — orquestrador principal.

Sobe a API (dashboard), o motor de detecção em background e expõe os
endpoints que o frontend consome. Coletores de log e o sniffer de rede
são processos/threads separados (veja README) para não travar a API.
"""
import hmac
import os
import secrets
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response
from pydantic import BaseModel

from auth import totp
from db import SessionLocal, Event, Alert, Vulnerability, ResponseAction, init_db
from detection.engine import run_detection_cycle
from response.active_response import handle_alert
from scanner.vuln_scanner import scan_host, ScanTargetNotAllowed

app = FastAPI(title="Sentinela", version="0.1.0")

# CORS restrito a localhost — sem isso, QUALQUER página aberta no seu
# navegador podia fazer fetch() contra localhost:8000 e disparar ações
# (ex: um scan) sem você saber.
#
# "null" NÃO está na lista de propósito — tinha ficado aqui antes (pro
# dashboard aberto como file:// funcionar) e isso foi um erro real: Origin:
# null também é o que uma <iframe sandbox> de QUALQUER página manda, então
# qualquer site aberto no mesmo navegador podia ler a resposta de /api/token
# através de uma iframe escondida. Provei isso rendendo o token de verdade
# num teste. A correção é servir o dashboard pela própria API (mesma
# origem, http://localhost:8000), não mais como arquivo local — veja o
# StaticFiles no fim deste arquivo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DETECTION_INTERVAL_SEC = 10

# --- Autenticação simples por token ------------------------------------------
# Não é um sistema de login — é o mínimo pra não deixar a API 100% aberta.
# Token fica em backend/.sentinela_token (gitignored), gerado uma vez e
# reaproveitado nas próximas subidas. Pode ser sobrescrito por env var.
# SENTINELA_DATA_DIR permite apontar pra um volume persistente (Docker) —
# sem isso, o token viveria só no filesystem do container, e sumiria a
# cada `docker compose down`, forçando reconfigurar o 2FA do zero toda
# vez. Por padrão (sem Docker), continua em backend/ como sempre foi.
_DATA_DIR = Path(os.environ.get("SENTINELA_DATA_DIR", Path(__file__).parent))
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_TOKEN_FILE = _DATA_DIR / ".sentinela_token"


def _load_or_create_token() -> str:
    env_token = os.environ.get("SENTINELA_API_TOKEN")
    if env_token:
        return env_token
    if _TOKEN_FILE.exists():
        return _TOKEN_FILE.read_text().strip()
    token = secrets.token_urlsafe(24)
    _TOKEN_FILE.write_text(token)
    return token


API_TOKEN = _load_or_create_token()

# --- Segundo fator (TOTP) -----------------------------------------------------
# Protege o momento mais sensível: pegar o token pela primeira vez. Sem
# isso, quem tivesse acesso a backend/.sentinela_token (cópia de backup,
# outro processo na máquina) já teria acesso total. Com TOTP, também
# precisa do código de 6 dígitos que muda a cada 30s — gerado por um
# segredo que só existe no seu app autenticador.
_TOTP_SECRET, _totp_is_new = totp.load_or_create_secret()

if _totp_is_new:
    _uri = totp.provisioning_uri(_TOTP_SECRET)
    print("\n" + "=" * 70)
    print("SENTINELA — configuração do segundo fator (2FA)")
    print("=" * 70)
    print(f"Segredo (se preferir digitar manualmente): {_TOTP_SECRET}")
    print(f"URI de provisionamento: {_uri}")
    print("Escaneie o QR code em http://localhost:8000/api/2fa/qr")
    print("(Google Authenticator, Authy, 1Password, etc.)")
    print("Esse setup só aparece uma vez — o segredo fica salvo em")
    print(".sentinela_totp_secret (gitignored).")
    print("=" * 70 + "\n")


def require_api_key(x_api_key: str = Header(default=None)):
    # hmac.compare_digest, não `!=` — comparação de string normal pode
    # vazar o token por timing attack (CPython compara char a char e sai
    # assim que acha diferença; compare_digest sempre compara tudo).
    if not x_api_key or not hmac.compare_digest(x_api_key, API_TOKEN):
        raise HTTPException(401, "Token inválido ou ausente (header X-API-Key).")


# --- Loop de detecção + resposta em background ------------------------------

def _background_loop():
    while True:
        try:
            run_detection_cycle()
            db = SessionLocal()
            try:
                # Só processa alerta aberto que ainda não teve nenhuma ação
                # registrada — sem isso, um alerta em dry_run (que nunca muda
                # de status) seria reprocessado a cada ciclo, pra sempre.
                already_handled = db.query(ResponseAction.alert_id).distinct()
                handled_ids = {r[0] for r in already_handled}
                open_alerts = (
                    db.query(Alert)
                    .filter(Alert.status == "open", ~Alert.id.in_(handled_ids) if handled_ids else True)
                    .all()
                )
                for alert in open_alerts:
                    result = handle_alert(alert)
                    if result == "applied":
                        alert.status = "mitigated"
                db.commit()
            finally:
                db.close()
        except Exception as e:
            print(f"[sentinela] erro no ciclo de detecção: {e}")
        time.sleep(DETECTION_INTERVAL_SEC)


@app.on_event("startup")
def startup():
    init_db()
    threading.Thread(target=_background_loop, daemon=True).start()


# --- Endpoints ----------------------------------------------------------------

@app.get("/api/events", dependencies=[Depends(require_api_key)])
def list_events(limit: int = 100, source: str = None):
    db = SessionLocal()
    try:
        q = db.query(Event).order_by(Event.timestamp.desc())
        if source:
            q = q.filter(Event.source == source)
        return [
            {"id": e.id, "timestamp": e.timestamp, "source": e.source, "src_ip": e.src_ip,
             "dst_ip": e.dst_ip, "dst_port": e.dst_port, "action": e.action,
             "outcome": e.outcome}
            for e in q.limit(limit).all()
        ]
    finally:
        db.close()


@app.get("/api/alerts", dependencies=[Depends(require_api_key)])
def list_alerts(status: str = None, limit: int = 100):
    db = SessionLocal()
    try:
        q = db.query(Alert).order_by(Alert.timestamp.desc())
        if status:
            q = q.filter(Alert.status == status)
        return [
            {"id": a.id, "timestamp": a.timestamp, "rule": a.rule, "mitre_id": a.mitre_id,
             "severity": a.severity, "src_ip": a.src_ip, "description": a.description,
             "status": a.status}
            for a in q.limit(limit).all()
        ]
    finally:
        db.close()


@app.post("/api/alerts/{alert_id}/ignore", dependencies=[Depends(require_api_key)])
def ignore_alert(alert_id: int):
    db = SessionLocal()
    try:
        alert = db.query(Alert).get(alert_id)
        if not alert:
            raise HTTPException(404, "Alerta não encontrado.")
        alert.status = "ignored"
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.get("/api/vulnerabilities", dependencies=[Depends(require_api_key)])
def list_vulnerabilities(host: str = None, limit: int = 200):
    db = SessionLocal()
    try:
        q = db.query(Vulnerability).order_by(Vulnerability.timestamp.desc())
        if host:
            q = q.filter(Vulnerability.host == host)
        return [
            {"id": v.id, "timestamp": v.timestamp, "host": v.host, "port": v.port,
             "service": v.service, "banner": v.banner, "cve_id": v.cve_id,
             "severity": v.severity, "cvss": v.cvss, "description": v.description}
            for v in q.limit(limit).all()
        ]
    finally:
        db.close()


class ScanRequest(BaseModel):
    host: str
    enrich_cve: bool = True


@app.post("/api/scan", dependencies=[Depends(require_api_key)])
def trigger_scan(req: ScanRequest):
    """Dispara o scanner de vulnerabilidades contra um host do seu lab."""
    try:
        findings = scan_host(req.host, enrich_cve=req.enrich_cve)
    except ScanTargetNotAllowed as e:
        raise HTTPException(403, str(e))
    return {"host": req.host, "open_ports_found": len(findings)}


@app.get("/api/responses", dependencies=[Depends(require_api_key)])
def list_responses(limit: int = 100):
    db = SessionLocal()
    try:
        q = db.query(ResponseAction).order_by(ResponseAction.timestamp.desc())
        return [
            {"id": r.id, "timestamp": r.timestamp, "alert_id": r.alert_id,
             "action": r.action, "target": r.target, "result": r.result, "detail": r.detail}
            for r in q.limit(limit).all()
        ]
    finally:
        db.close()


@app.get("/api/token")
def get_token(request: Request, code: str = ""):
    """
    Bootstrap do token pro dashboard local, agora atrás do segundo fator:
    só devolve o token com um código TOTP válido (?code=123456). Sem o
    código certo do seu app autenticador, nem estar em localhost basta.
    """
    if request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Só acessível de localhost.")
    if not totp.verify_code(_TOTP_SECRET, code):
        raise HTTPException(401, "Código 2FA inválido ou ausente.")
    return {"token": API_TOKEN}


@app.get("/api/2fa/qr")
def get_2fa_qr(request: Request):
    """QR code pra configurar o app autenticador — só pra setup inicial,
    não precisa de token (seria chicken-and-egg)."""
    if request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Só acessível de localhost.")
    png = totp.qr_png_bytes(totp.provisioning_uri(_TOTP_SECRET))
    return Response(content=png, media_type="image/png")


@app.get("/api/summary", dependencies=[Depends(require_api_key)])
def summary():
    db = SessionLocal()
    try:
        return {
            "total_events": db.query(Event).count(),
            "open_alerts": db.query(Alert).filter(Alert.status == "open").count(),
            "mitigated_alerts": db.query(Alert).filter(Alert.status == "mitigated").count(),
            "vulnerabilities": db.query(Vulnerability).count(),
        }
    finally:
        db.close()


# --- Dashboard (mesma origem da API) -----------------------------------------
# Montado por ÚLTIMO, depois de toda rota /api/* — assim elas continuam
# tendo prioridade de match, e StaticFiles só pega o resto ("/", assets).
# Serve o dashboard em http://localhost:8000/ em vez de abrir o HTML como
# arquivo local: isso faz o Origin ser http://localhost:8000 de verdade,
# eliminando a necessidade de aceitar Origin: null no CORS (que era
# explorável por qualquer página via iframe sandboxed — veja o comentário
# no CORSMiddleware acima).
_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="dashboard")
