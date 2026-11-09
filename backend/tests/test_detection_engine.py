"""
Testa cada regra de detecção isoladamente: dado um conjunto de Events,
a regra certa dispara (ou não dispara, nos casos de falso positivo que
importa evitar). Usa o banco em memória da fixture `session`.
"""
from datetime import timedelta

from db import Event, Alert, utcnow
from detection.engine import (
    rule_ssh_brute_force, rule_web_injection, rule_port_scan,
    rule_possible_exfiltration, BRUTE_FORCE_THRESHOLD, PORT_SCAN_THRESHOLD,
)


def _add_event(session, **kwargs):
    e = Event(timestamp=utcnow(), **kwargs)
    session.add(e)
    session.commit()
    return e


def test_brute_force_triggers_at_threshold(session):
    for _ in range(BRUTE_FORCE_THRESHOLD):
        _add_event(session, source="auth_log", src_ip="203.0.113.44",
                    action="ssh_login_failed", outcome="failure")

    rule_ssh_brute_force(session)

    alerts = session.query(Alert).filter(Alert.rule == "ssh_brute_force").all()
    assert len(alerts) == 1
    assert alerts[0].mitre_id == "T1110"
    assert alerts[0].src_ip == "203.0.113.44"


def test_brute_force_does_not_trigger_below_threshold(session):
    for _ in range(BRUTE_FORCE_THRESHOLD - 1):
        _add_event(session, source="auth_log", src_ip="203.0.113.44",
                    action="ssh_login_failed", outcome="failure")

    rule_ssh_brute_force(session)

    assert session.query(Alert).count() == 0


def test_brute_force_does_not_duplicate_alert(session):
    """Mesma situação, regra rodando duas vezes — não deve virar 2 alertas."""
    for _ in range(BRUTE_FORCE_THRESHOLD):
        _add_event(session, source="auth_log", src_ip="203.0.113.44",
                    action="ssh_login_failed", outcome="failure")

    rule_ssh_brute_force(session)
    rule_ssh_brute_force(session)  # roda de novo, simula o ciclo de 10s

    assert session.query(Alert).count() == 1


def test_sqli_detected(session):
    _add_event(session, source="web_log", src_ip="198.51.100.23",
                action="http_sqli_attempt", outcome="blocked")

    rule_web_injection(session)

    alerts = session.query(Alert).filter(Alert.rule == "web_sqli_attempt").all()
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"


def test_xss_detected(session):
    _add_event(session, source="web_log", src_ip="198.51.100.77",
                action="http_xss_attempt", outcome="blocked")

    rule_web_injection(session)

    alerts = session.query(Alert).filter(Alert.rule == "web_xss_attempt").all()
    assert len(alerts) == 1


def test_normal_http_request_does_not_trigger(session):
    _add_event(session, source="web_log", src_ip="198.51.100.1",
                action="http_request", outcome="success")

    rule_web_injection(session)

    assert session.query(Alert).count() == 0


def test_port_scan_triggers_at_threshold(session):
    for port in range(PORT_SCAN_THRESHOLD):
        _add_event(session, source="network", src_ip="192.168.56.20",
                    dst_ip="192.168.56.10", dst_port=2000 + port, action="tcp_syn")

    rule_port_scan(session)

    alerts = session.query(Alert).filter(Alert.rule == "network_port_scan").all()
    assert len(alerts) == 1
    assert alerts[0].mitre_id == "T1046"


def test_port_scan_ignores_few_ports(session):
    for port in range(3):  # bem abaixo do limiar
        _add_event(session, source="network", src_ip="192.168.56.20",
                    dst_ip="192.168.56.10", dst_port=2000 + port, action="tcp_syn")

    rule_port_scan(session)

    assert session.query(Alert).count() == 0


def test_port_scan_same_port_repeated_does_not_count_as_distinct(session):
    # 20 conexões na MESMA porta não é port scan (é só um SYN repetido).
    for _ in range(PORT_SCAN_THRESHOLD + 5):
        _add_event(session, source="network", src_ip="192.168.56.20",
                    dst_ip="192.168.56.10", dst_port=22, action="tcp_syn")

    rule_port_scan(session)

    assert session.query(Alert).count() == 0
