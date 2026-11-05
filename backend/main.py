"""
Sentinela — orquestrador principal.

Sobe a API (dashboard), o motor de detecção em background e expõe os
endpoints que o frontend consome. Coletores de log e o sniffer de rede
são processos/threads separados (veja README) para não travar a API.
"""
import os
import secrets
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import SessionLocal, Event, Alert, Vulnerability, ResponseAction, init_db
from detection.engine import run_detection_cycle
from response.active_response import handle_alert
from scanner.vuln_scanner import scan_host, ScanTargetNotAllowed

app = FastAPI(title="Sentinela", version="0.1.0")

# CORS restrito: sem isso, QUALQUER página aberta no seu navegador podia
# fazer fetch() contra localhost:8000 e disparar ações (ex: um scan) sem
# você saber — é CSRF básico contra uma API sem proteção. O dashboard é
# aberto como arquivo local (file://), que o navegador manda como
# Origin: null, por isso "null" também precisa estar na lista.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "null"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DETECTION_INTERVAL_SEC = 10

# --- Autenticação simples por token ------------------------------------------
# Não é um sistema de login — é o mínimo pra não deixar a API 100% aberta.
# Token fica em backend/.sentinela_token (gitignored), gerado uma vez e
# reaproveitado nas próximas subidas. Pode ser sobrescrito por env var.
_TOKEN_FILE = Path(__file__).parent / ".sentinela_token"


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


def require_api_key(x_api_key: str = Header(default=None)):
    if x_api_key != API_TOKEN:
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
def get_token(request: Request):
    """
    Bootstrap do token pro dashboard local — sem isso, o arquivo HTML
    estático não teria como saber o token gerado no backend sem você
    copiar manualmente. Só responde pra quem está em localhost: o CORS
    restrito acima já impede página de outra origem de LER essa resposta
    no navegador, e isso reforça checando a origem da conexão TCP também.
    """
    if request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Só acessível de localhost.")
    return {"token": API_TOKEN}


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
