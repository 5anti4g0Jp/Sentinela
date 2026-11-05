"""
Módulo 3 — Scanner de vulnerabilidades: varre hosts da sua própria rede/lab,
identifica portas abertas, faz banner grabbing e tenta associar a um CVE
conhecido via NVD (opcional/best-effort).

Sem dependência de nmap binário — usa sockets puros para portabilidade.
Para scans mais completos depois, trocar por `python-nmap` é trivial.
"""
import ipaddress
import os
import socket
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

import requests

from db import SessionLocal, Vulnerability

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Escopo do projeto é "só o seu lab" — isso precisa ser imposto pelo
# código, não só prometido no README. Por padrão só aceita host que
# resolve pra IP privado/loopback. SENTINELA_SCAN_ALLOW_PUBLIC=1 destrava
# isso conscientemente (ex: você quer testar contra um host de CTF
# autorizado, fora da sua rede local).
ALLOW_PUBLIC_SCAN = os.environ.get("SENTINELA_SCAN_ALLOW_PUBLIC") == "1"


class ScanTargetNotAllowed(Exception):
    """Host pedido não é privado/loopback e SENTINELA_SCAN_ALLOW_PUBLIC não está setado."""


def _assert_host_in_scope(host: str) -> str:
    """Resolve o host e garante que é privado/loopback, a menos que
    explicitamente destravado. Retorna o IP resolvido."""
    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ScanTargetNotAllowed(f"Não foi possível resolver '{host}': {e}")

    if ALLOW_PUBLIC_SCAN:
        return resolved

    ip = ipaddress.ip_address(resolved)
    if not (ip.is_private or ip.is_loopback):
        raise ScanTargetNotAllowed(
            f"'{host}' resolve pra {resolved}, que não é privado/loopback. "
            "O Sentinela só varre seu próprio lab por padrão — isso não é "
            "limitação técnica, é a regra de escopo do projeto. Se você tem "
            "autorização explícita pra escanear esse host, rode com "
            "SENTINELA_SCAN_ALLOW_PUBLIC=1 conscientemente."
        )
    return resolved


def _utcnow():
    return datetime.now(timezone.utc)


def grab_banner(host: str, port: int, timeout: float = 1.5) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                return sock.recv(256).decode(errors="ignore").strip() or None
            except socket.timeout:
                # alguns serviços só respondem depois de receber algo (ex: HTTP)
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    return sock.recv(256).decode(errors="ignore").strip() or None
                except Exception:
                    return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_port(host: str, port: int) -> Optional[dict]:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            banner = grab_banner(host, port)
            return {"port": port, "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def lookup_cve(keyword: str, timeout: float = 5.0) -> List[dict]:
    """
    Busca best-effort na NVD por palavra-chave extraída do banner
    (ex: "OpenSSH 7.2"). Sem chave de API o rate limit é baixo — use com
    moderação e trate falha/timeout como "sem dado", nunca como erro fatal.
    """
    try:
        resp = requests.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": 3},
                             timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    cvss = metrics[key][0]["cvssData"]["baseScore"]
                    break
            results.append({
                "cve_id": cve["id"],
                "cvss": cvss,
                "description": cve["descriptions"][0]["value"] if cve.get("descriptions") else "",
            })
        return results
    except Exception:
        return []  # sem internet / rate limit / NVD fora do ar -> segue sem enriquecer


def _severity_from_cvss(cvss: Optional[float]) -> str:
    if cvss is None:
        return "info"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def scan_host(host: str, ports: List[int] = None, enrich_cve: bool = True) -> List[dict]:
    """Varre um host e persiste os achados. Retorna a lista de achados também."""
    _assert_host_in_scope(host)  # levanta ScanTargetNotAllowed se fora do escopo
    ports = ports or COMMON_PORTS
    findings = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            if result := future.result():
                findings.append(result)

    db = SessionLocal()
    try:
        for f in findings:
            cve_matches = []
            if enrich_cve and f["banner"]:
                cve_matches = lookup_cve(f["banner"][:60])

            if cve_matches:
                for cve in cve_matches:
                    db.add(Vulnerability(
                        timestamp=_utcnow(), host=host, port=f["port"],
                        banner=f["banner"], cve_id=cve["cve_id"],
                        cvss=cve["cvss"], severity=_severity_from_cvss(cve["cvss"]),
                        description=cve["description"][:500],
                    ))
            else:
                db.add(Vulnerability(
                    timestamp=_utcnow(), host=host, port=f["port"],
                    banner=f["banner"], severity="info",
                    description="Porta aberta sem CVE correlacionado automaticamente.",
                ))
        db.commit()
    finally:
        db.close()

    return findings
