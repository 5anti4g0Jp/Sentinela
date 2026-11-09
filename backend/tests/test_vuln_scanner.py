"""
Testa o scanner sem precisar de rede real: a classificação de severidade
é pura, e o guard de escopo (host privado/loopback) e a deduplicação por
host são testados com mocks — sem isso, "testar o scanner" significaria
sempre precisar de um serviço de verdade escutando em algum lugar.
"""
from unittest.mock import patch

import pytest

from db import Vulnerability, utcnow
from scanner.vuln_scanner import (
    _severity_from_cvss, _assert_host_in_scope, ScanTargetNotAllowed, scan_host,
)


# --- severidade por CVSS ------------------------------------------------------

@pytest.mark.parametrize("cvss,expected", [
    (None, "info"),
    (9.8, "critical"),
    (9.0, "critical"),
    (8.9, "high"),
    (7.0, "high"),
    (6.9, "medium"),
    (4.0, "medium"),
    (3.9, "low"),
    (0.0, "low"),
])
def test_severity_from_cvss(cvss, expected):
    assert _severity_from_cvss(cvss) == expected


# --- escopo (host privado/loopback) ------------------------------------------

def test_private_host_allowed():
    ip = _assert_host_in_scope("127.0.0.1")
    assert ip == "127.0.0.1"


def test_public_host_rejected():
    # 8.8.8.8 é DNS público do Google — nunca deve passar no escopo padrão.
    with pytest.raises(ScanTargetNotAllowed):
        _assert_host_in_scope("8.8.8.8")


def test_unresolvable_host_rejected():
    with pytest.raises(ScanTargetNotAllowed):
        _assert_host_in_scope("este-host-nao-existe-de-verdade.invalid")


# --- deduplicação por host (bug achado testando no notebook real) -----------

def test_rescanning_same_host_does_not_duplicate(session):
    with patch("scanner.vuln_scanner.scan_port", return_value={"port": 22, "banner": "SSH-2.0-Teste"}):
        scan_host("127.0.0.1", ports=[22], enrich_cve=False)
        scan_host("127.0.0.1", ports=[22], enrich_cve=False)

    rows = session.query(Vulnerability).filter(Vulnerability.host == "127.0.0.1").all()
    assert len(rows) == 1


def test_scanning_different_host_does_not_wipe_others(session):
    session.add(Vulnerability(timestamp=utcnow(), host="192.168.56.10", port=80,
                               banner="outro host", severity="info"))
    session.commit()

    with patch("scanner.vuln_scanner.scan_port", return_value={"port": 22, "banner": "SSH-2.0-Teste"}):
        scan_host("127.0.0.1", ports=[22], enrich_cve=False)

    assert session.query(Vulnerability).filter(Vulnerability.host == "192.168.56.10").count() == 1
