"""
Módulo 2 — Motor de detecção: lê Events e aplica regras mapeadas ao MITRE
ATT&CK, gerando Alerts quando um padrão suspeito é identificado.

Design: cada regra é uma função pura (lista de Events recentes -> lista de
alertas). Isso deixa fácil adicionar regra nova sem tocar no resto.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from db import SessionLocal, Event, Alert, utcnow

# --- Configuração das regras -------------------------------------------------

BRUTE_FORCE_THRESHOLD = 5       # tentativas falhas
BRUTE_FORCE_WINDOW_MIN = 2      # na mesma janela de tempo (minutos)

PORT_SCAN_THRESHOLD = 15        # portas distintas tocadas pelo mesmo IP
PORT_SCAN_WINDOW_MIN = 1

EXFIL_EVENT_THRESHOLD = 200     # eventos de rede do mesmo IP na janela
EXFIL_WINDOW_MIN = 1


def _recent_events(db, source: str, since_minutes: int) -> List[Event]:
    cutoff = utcnow() - timedelta(minutes=since_minutes)
    return (
        db.query(Event)
        .filter(Event.source == source, Event.timestamp >= cutoff)
        .all()
    )


def _already_open(db, rule: str, src_ip: str) -> bool:
    """Evita duplicar alerta aberto para o mesmo IP/regra em curto período."""
    cutoff = utcnow() - timedelta(minutes=5)
    return (
        db.query(Alert)
        .filter(Alert.rule == rule, Alert.src_ip == src_ip, Alert.timestamp >= cutoff)
        .first()
        is not None
    )


def _raise_alert(db, rule, mitre_id, severity, src_ip, description):
    if _already_open(db, rule, src_ip):
        return None
    alert = Alert(
        timestamp=utcnow(), rule=rule, mitre_id=mitre_id, severity=severity,
        src_ip=src_ip, description=description, status="open",
    )
    db.add(alert)
    db.commit()
    return alert


# --- Regras ------------------------------------------------------------------

def rule_ssh_brute_force(db):
    events = _recent_events(db, "auth_log", BRUTE_FORCE_WINDOW_MIN)
    fails_by_ip = defaultdict(int)
    for e in events:
        if e.action == "ssh_login_failed":
            fails_by_ip[e.src_ip] += 1

    for ip, count in fails_by_ip.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            _raise_alert(
                db, rule="ssh_brute_force", mitre_id="T1110", severity="high",
                src_ip=ip,
                description=f"{count} tentativas de login SSH falhas em "
                             f"{BRUTE_FORCE_WINDOW_MIN} min a partir de {ip}.",
            )


def rule_web_injection(db):
    events = _recent_events(db, "web_log", 5)
    for e in events:
        if e.action == "http_sqli_attempt":
            _raise_alert(
                db, rule="web_sqli_attempt", mitre_id="T1190", severity="critical",
                src_ip=e.src_ip,
                description=f"Padrão de SQL Injection detectado na requisição "
                             f"vinda de {e.src_ip}.",
            )
        elif e.action == "http_xss_attempt":
            _raise_alert(
                db, rule="web_xss_attempt", mitre_id="T1190", severity="high",
                src_ip=e.src_ip,
                description=f"Padrão de XSS detectado na requisição vinda de {e.src_ip}.",
            )


def rule_port_scan(db):
    events = _recent_events(db, "network", PORT_SCAN_WINDOW_MIN)
    ports_by_ip = defaultdict(set)
    for e in events:
        if e.action == "tcp_syn" and e.dst_port:
            ports_by_ip[e.src_ip].add(e.dst_port)

    for ip, ports in ports_by_ip.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            _raise_alert(
                db, rule="network_port_scan", mitre_id="T1046", severity="medium",
                src_ip=ip,
                description=f"{len(ports)} portas distintas sondadas por {ip} em "
                             f"{PORT_SCAN_WINDOW_MIN} min (possível reconhecimento).",
            )


def rule_possible_exfiltration(db):
    events = _recent_events(db, "network", EXFIL_WINDOW_MIN)
    count_by_ip = defaultdict(int)
    for e in events:
        count_by_ip[e.src_ip] += 1

    for ip, count in count_by_ip.items():
        if count >= EXFIL_EVENT_THRESHOLD:
            _raise_alert(
                db, rule="network_volume_anomaly", mitre_id="T1041", severity="high",
                src_ip=ip,
                description=f"Volume anormal de tráfego ({count} pacotes) de {ip} "
                             f"em {EXFIL_WINDOW_MIN} min — possível exfiltração.",
            )


RULES = [
    rule_ssh_brute_force,
    rule_web_injection,
    rule_port_scan,
    rule_possible_exfiltration,
]


def run_detection_cycle():
    db = SessionLocal()
    try:
        for rule in RULES:
            rule(db)
    finally:
        db.close()
