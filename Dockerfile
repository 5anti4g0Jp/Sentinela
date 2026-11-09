# Build ainda não validado de ponta a ponta: o sandbox onde isso foi
# escrito tem um daemon Docker, mas os containers que ele cria não têm
# rota de rede pra internet (só a shell principal, via proxy do agente,
# tem) — então `apt-get` dentro do build sempre falha aqui por DNS, não
# por configuração errada. Valide com `docker compose build` numa máquina
# com Docker normal e me avise se quebrar.

FROM python:3.12-slim

# libpcap0.8: dependência de sistema do scapy pra captura com filtro BPF.
# Sem ela, o sniffer cai no modo sem filtro (veja backend/network/sniffer.py)
# — funciona, mas com a lib de verdade a captura com filtro é mais rápida.
# Debian trixie (base desta imagem) renomeou o pacote pra libpcap0.8t64
# (migração t64); o fallback cobre bases mais antigas que ainda usam o
# nome original.
RUN apt-get update && (apt-get install -y --no-install-recommends libpcap0.8t64 \
    || apt-get install -y --no-install-recommends libpcap0.8) \
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
