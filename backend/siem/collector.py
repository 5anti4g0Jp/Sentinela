"""
Módulo 1 — SIEM: coleta e normaliza logs em Events.

Lê arquivos de log tipo auth.log (SSH) e access.log (Nginx/Apache) em modo
"tail -f" e grava cada linha relevante como Event normalizado no banco.
Isso é a base de dados que a detecção (módulo 2) consome.
"""
import re
import time
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote

from db import SessionLocal, Event, utcnow

# --- Padrões de parsing -----------------------------------------------------

# Exemplo de linha real do auth.log do Linux:
# "Oct 31 10:15:02 host sshd[1234]: Failed password for root from 10.0.0.5 port 51515 ssh2"
SSH_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)

# Exemplo de linha de access.log no formato combined do Nginx/Apache:
# '203.0.113.5 - - [31/Oct/2026:10:15:02 +0000] "GET /admin?id=1 OR 1=1 HTTP/1.1" 403 512'
HTTP_LOG_RE = re.compile(
    r'(?P<ip>[\d.]+) \S+ \S+ \[.*?\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3})'
)

SQLI_PATTERNS = re.compile(r"(?i)(union\s+select|or\s+1=1|--|'\s*or\s*')")
XSS_PATTERNS = re.compile(r"(?i)(<script|onerror=|javascript:)")


def tail_file(path: Path) -> Iterator[str]:
    """Segue um arquivo como `tail -f`, cedendo cada linha nova."""
    with open(path, "r", errors="ignore") as f:
        f.seek(0, 2)  # vai para o fim — só processa o que chegar daqui em diante
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def parse_ssh_line(line: str):
    if m := SSH_FAILED_RE.search(line):
        return dict(source="auth_log", src_ip=m["ip"], user=m["user"],
                     action="ssh_login_failed", outcome="failure", raw=line)
    if m := SSH_ACCEPTED_RE.search(line):
        return dict(source="auth_log", src_ip=m["ip"], user=m["user"],
                     action="ssh_login_success", outcome="success", raw=line)
    return None


def parse_http_line(line: str):
    m = HTTP_LOG_RE.search(line)
    if not m:
        return None
    # Decodifica %XX antes de casar o padrão — sem isso, "OR%201=1" (como
    # navegador/curl/sqlmap mandam de verdade, já que espaço cru não é
    # válido no request-target do HTTP) passava direto sem ser pego,
    # porque \s não bate em "%20". Achado testando com pytest de verdade,
    # não хipotético: um SQLi real sem o acaso de ter "--" no payload
    # escapava silenciosamente. unquote() é seguro aqui mesmo com %
    # literal malformado — devolve a string como está nesse caso.
    decoded_path = unquote(m["path"])
    action = "http_request"
    if SQLI_PATTERNS.search(decoded_path):
        action = "http_sqli_attempt"
    elif XSS_PATTERNS.search(decoded_path):
        action = "http_xss_attempt"
    return dict(source="web_log", src_ip=m["ip"], action=action,
                outcome="blocked" if m["status"].startswith(("4", "5")) else "success",
                raw=line)


def ingest_line(parsed: dict):
    db = SessionLocal()
    try:
        db.add(Event(timestamp=utcnow(), **parsed))
        db.commit()
    finally:
        db.close()


def run_collector(log_path: str, kind: str):
    """
    kind: "ssh" ou "http". Roda indefinidamente — pensado para rodar como
    processo/thread de fundo (veja main.py).
    """
    parser = parse_ssh_line if kind == "ssh" else parse_http_line
    for line in tail_file(Path(log_path)):
        if parsed := parser(line):
            ingest_line(parsed)
