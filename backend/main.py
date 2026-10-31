"""
Sentinela — orquestrador principal.

Sobe a API (dashboard), o motor de detecção em background e expõe os
endpoints que o frontend consome. Coletores de log e o sniffer de rede
são processos/threads separados (veja README) para não travar a API.
"""
import threading
import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import SessionLocal, Event, Alert, Vulnerability, ResponseAction, init_db
from detection.engine import run_detection_cycle
from response.active_response import handle_alert
from scanner.vuln_scanner import scan_host

app = FastAPI(title="Sentinela", version="0.1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

DETECTION_INTERVAL_SEC = 10


# --- Loop de detecção + resposta em background ------------------------------

def _background_loop():
    while True:
        try:
            run_detection_cycle()
            db = SessionLocal()
            try:
                open_alerts = db.query(Alert).filter(Alert.status == "open").all()
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

@app.get("/api/events")
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


@app.get("/api/alerts")
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


@app.post("/api/alerts/{alert_id}/ignore")
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


@app.get("/api/vulnerabilities")
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


@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    """Dispara o scanner de vulnerabilidades contra um host do seu lab."""
    findings = scan_host(req.host, enrich_cve=req.enrich_cve)
    return {"host": req.host, "open_ports_found": len(findings)}


@app.get("/api/responses")
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


@app.get("/api/summary")
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
