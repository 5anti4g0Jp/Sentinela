"""
Segundo fator (TOTP) — o mesmo protocolo do Google Authenticator/Authy.

Modelo de ameaça real que isso cobre: o Sentinela não tem login de
usuário/senha, só um token estático em arquivo. Se esse arquivo vazar
(cópia de backup, outro processo na máquina, etc.), quem tiver o token
tem acesso total. TOTP exige também um código de 6 dígitos que muda a
cada 30s, gerado por um segredo que só existe no seu celular/app — então
vazar só o arquivo do token não basta mais.

O que isso NÃO é: não é MFA de conta de usuário (não existe conceito de
"usuário" aqui, é ferramenta de uso pessoal). É uma segunda barreira pra
pegar o token inicial, não uma re-autenticação por ação individual.
"""
import io
from pathlib import Path

import pyotp
import qrcode

_SECRET_FILE = Path(__file__).parent.parent / ".sentinela_totp_secret"


def load_or_create_secret() -> tuple[str, bool]:
    """Retorna (segredo, foi_criado_agora)."""
    if _SECRET_FILE.exists():
        return _SECRET_FILE.read_text().strip(), False
    secret = pyotp.random_base32()
    _SECRET_FILE.write_text(secret)
    return secret, True


def provisioning_uri(secret: str, account_name: str = "sentinela-local") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name="Sentinela")


def verify_code(secret: str, code: str) -> bool:
    if not code or not code.isdigit():
        return False
    # valid_window=1 tolera 1 passo de 30s pra frente/trás (relógio do
    # celular levemente dessincronizado) — não abre janela grande o
    # suficiente pra ser prático de atacar por força bruta junto.
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_png_bytes(uri: str) -> bytes:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
