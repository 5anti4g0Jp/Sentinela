"""
Testa o parser de log SSH/HTTP com linhas REAIS (copiadas do formato de
verdade do Linux), não inventadas. Isso é o mesmo regex que validei
manualmente contra auth.log no início do projeto — agora fica garantido
em CI, não depende de alguém lembrar de testar de novo.
"""
from siem.collector import parse_ssh_line, parse_http_line


def test_ssh_failed_password():
    line = "Oct 31 16:20:01 lab sshd[1234]: Failed password for root from 198.51.100.9 port 51515 ssh2"
    result = parse_ssh_line(line)
    assert result["src_ip"] == "198.51.100.9"
    assert result["user"] == "root"
    assert result["action"] == "ssh_login_failed"
    assert result["outcome"] == "failure"


def test_ssh_failed_invalid_user():
    line = "Oct 31 16:20:02 lab sshd[1234]: Failed password for invalid user admin from 198.51.100.9 port 51516 ssh2"
    result = parse_ssh_line(line)
    assert result["src_ip"] == "198.51.100.9"
    assert result["user"] == "admin"
    assert result["action"] == "ssh_login_failed"


def test_ssh_accepted_password():
    line = "Oct 31 16:20:05 lab sshd[1235]: Accepted password for pedro from 10.0.0.5 port 52000 ssh2"
    result = parse_ssh_line(line)
    assert result["src_ip"] == "10.0.0.5"
    assert result["user"] == "pedro"
    assert result["action"] == "ssh_login_success"
    assert result["outcome"] == "success"


def test_ssh_ignores_unrelated_lines():
    # Uma linha de CRON não é evento de login — não pode virar Event.
    line = "Oct 31 16:20:06 lab CRON[999]: pam_unix(cron:session): session opened for user root"
    assert parse_ssh_line(line) is None


def test_http_sqli_detected():
    # Espaço cru não é válido no request-target do HTTP — navegador/curl/
    # sqlmap mandam %20 de verdade. Testar com espaço literal mascarava
    # um bug real (achado rodando esse teste): ver test_http_sqli_detected_
    # without_comment_marker abaixo.
    line = '203.0.113.5 - - [31/Oct/2026:10:15:02 +0000] "GET /login?user=admin%27%20OR%201=1-- HTTP/1.1" 403 512'
    result = parse_http_line(line)
    assert result["action"] == "http_sqli_attempt"
    assert result["src_ip"] == "203.0.113.5"
    assert result["outcome"] == "blocked"


def test_http_sqli_detected_without_comment_marker():
    # Sem o '--' no final — só "OR 1=1" codificado. Antes do fix de
    # unquote() em parse_http_line, isso passava como http_request comum,
    # sem detectar o SQLi. Regressão real, não teórica.
    line = '203.0.113.5 - - [31/Oct/2026:10:15:02 +0000] "GET /login?user=admin%27%20OR%201=1 HTTP/1.1" 403 512'
    result = parse_http_line(line)
    assert result["action"] == "http_sqli_attempt"


def test_http_xss_detected():
    line = '203.0.113.5 - - [31/Oct/2026:10:15:02 +0000] "GET /comment?x=<script>alert(1)</script> HTTP/1.1" 403 512'
    result = parse_http_line(line)
    assert result["action"] == "http_xss_attempt"


def test_http_normal_request_not_flagged():
    line = '203.0.113.5 - - [31/Oct/2026:10:15:02 +0000] "GET /index.html HTTP/1.1" 200 1024'
    result = parse_http_line(line)
    assert result["action"] == "http_request"
    assert result["outcome"] == "success"
