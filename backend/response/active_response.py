"""
Módulo 5 — Resposta ativa DEFENSIVA.

Regra de design inegociável: toda ação aqui atua dentro do próprio
perímetro (seu firewall, seus hosts, suas sessões). NUNCA envia tráfego
ofensivo contra o IP de origem do ataque — isso seria hack-back, ilegal
e tecnicamente furado (IP de origem costuma ser spoofado/de terceiro).

Por padrão DRY_RUN=True: loga o que faria, sem executar. Mude para False
só quando tiver validado em ambiente de lab.
"""
import platform
import subprocess
from datetime import datetime, timezone

from db import SessionLocal, ResponseAction

DRY_RUN = True  # mude para False conscientemente, em ambiente de lab

# ban_ip/unban_ip chamam iptables direto — existe só em Linux. Em Windows
# nativo ou macOS isso falharia com um erro críptico de subprocess; melhor
# avisar com clareza o que fazer, em vez de deixar o ResponseAction gravado
# com "[Errno 2] No such file or directory: 'iptables'".
_IS_LINUX = platform.system() == "Linux"


def _utcnow():
    return datetime.now(timezone.utc)


def _log_action(alert_id, action, target, result, detail=""):
    db = SessionLocal()
    try:
        db.add(ResponseAction(
            timestamp=_utcnow(), alert_id=alert_id, action=action,
            target=target, result=result, detail=detail,
        ))
        db.commit()
    finally:
        db.close()


def ban_ip(ip: str, alert_id: int = None) -> str:
    """Bloqueia o IP no firewall local (iptables). Ação reversível e local."""
    if DRY_RUN:
        _log_action(alert_id, "ban_ip", ip, "dry_run",
                     "DRY_RUN ativo — nenhuma regra de firewall foi aplicada.")
        return "dry_run"

    if not _IS_LINUX:
        msg = (f"iptables só existe em Linux (sistema atual: {platform.system()}). "
               "Rode o backend dentro do WSL2/VM Linux pra resposta ativa funcionar "
               "de verdade — veja docs/wsl2-setup.md.")
        _log_action(alert_id, "ban_ip", ip, "failed", msg)
        return "failed"

    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        _log_action(alert_id, "ban_ip", ip, "applied", f"Executado: {' '.join(cmd)}")
        return "applied"
    except Exception as e:
        _log_action(alert_id, "ban_ip", ip, "failed", str(e))
        return "failed"


def unban_ip(ip: str, alert_id: int = None) -> str:
    if DRY_RUN:
        _log_action(alert_id, "unban_ip", ip, "dry_run", "DRY_RUN ativo.")
        return "dry_run"

    if not _IS_LINUX:
        _log_action(alert_id, "unban_ip", ip, "failed",
                     f"iptables só existe em Linux (sistema atual: {platform.system()}).")
        return "failed"

    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        _log_action(alert_id, "unban_ip", ip, "applied", f"Executado: {' '.join(cmd)}")
        return "applied"
    except Exception as e:
        _log_action(alert_id, "unban_ip", ip, "failed", str(e))
        return "failed"


# Mapa de resposta automática por severidade de alerta — ajuste conforme a
# tolerância a falso positivo do seu ambiente. Severidade "critical"/"high"
# dispara ban automático; abaixo disso só fica registrado para análise.
AUTO_RESPONSE_SEVERITIES = {"critical", "high"}


def handle_alert(alert) -> str:
    """
    Decide e aplica resposta para um Alert, respeitando o mapa acima.
    Chamado pelo loop principal depois de cada ciclo de detecção.
    """
    if alert.severity in AUTO_RESPONSE_SEVERITIES:
        return ban_ip(alert.src_ip, alert_id=alert.id)
    _log_action(alert.id, "none", alert.src_ip, "dry_run",
                 f"Severidade '{alert.severity}' abaixo do limiar de resposta automática.")
    return "no_action"
