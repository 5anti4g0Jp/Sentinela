# NÃO TESTADO em build real — a sandbox onde isso foi escrito não tem
# daemon Docker disponível. Escrito com cuidado (build context = raiz do
# repo, de propósito, porque o dashboard é servido a partir de ../frontend
# relativo ao backend/main.py — um Dockerfile dentro de backend/ só
# teria acesso à própria pasta e quebraria isso). Valide com
# `docker build -t sentinela .` a partir da raiz, e me avise se quebrar.

FROM python:3.12-slim

# libpcap0.8: dependência de sistema do scapy pra captura com filtro BPF.
# Sem ela, o sniffer cai no modo sem filtro (veja backend/network/sniffer.py)
# — funciona, mas com a lib de verdade a captura com filtro é mais rápida.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY frontend/ frontend/

WORKDIR /app/backend

EXPOSE 8000

# Sem --reload em produção/container — isso é só pra dev local.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
