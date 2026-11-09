#!/bin/bash
# Atalho pra subir o Sentinela sem precisar lembrar os 3 comandos toda vez.
# Uso: ~/Sentinela/backend/iniciar.sh

set -e
cd "$(dirname "$0")"

if ! [ -d .venv ]; then
    echo "Ambiente virtual não encontrado. Rode primeiro:"
    echo "  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

source .venv/bin/activate

# Se já tiver um uvicorn rodando nessa porta, não tenta subir outro —
# só avisa e sai, em vez de dar erro feio de "Address already in use".
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/2fa/qr 2>/dev/null | grep -q "200\|403"; then
    echo "O Sentinela já está rodando em http://localhost:8000/"
    echo "(se quiser reiniciar, feche a aba do terminal onde ele está rodando antes)"
    exit 0
fi

echo "Subindo o Sentinela..."
uvicorn main:app --reload
