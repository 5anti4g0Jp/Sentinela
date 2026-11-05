# Rodando o Sentinela no Windows (via WSL2)

O projeto usa `iptables` (resposta ativa) e caminhos de log tipo
`/var/log/auth.log` (coletor SIEM), que só existem em Linux. A forma mais
simples de rodar tudo sem reescrever essas partes é usar o **WSL2**
(Linux de verdade, dentro do Windows).

## 1. Instalar o WSL2

No PowerShell **como administrador**:

```powershell
wsl --install -d Ubuntu
```

Reinicia o notebook quando pedir. Depois, abre "Ubuntu" no menu iniciar e
define um usuário/senha Linux (só local, não é sua conta Windows).

Se o `wsl --install` falhar, verifica se a virtualização está ligada na
BIOS/UEFI (em notebooks com antivírus corporativo ou Hyper-V desligado,
às vezes precisa habilitar manualmente — a mensagem de erro do comando
geralmente diz o que falta).

## 2. Dentro do Ubuntu (WSL2), preparar o projeto

```bash
sudo apt update
sudo apt install -y libpcap0.8 python3-venv python3-pip git

# se o projeto já estiver no GitHub:
git clone <url-do-seu-repo> sentinela
cd sentinela/backend

# se não, copia a pasta do projeto do Windows pro WSL (muito mais rápido
# rodar daqui dentro do que do /mnt/c/... do Windows):
# cp -r /mnt/c/Users/<voce>/caminho/sentinela ~/sentinela
```

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Rodar

```bash
# API + loop de detecção + resposta
uvicorn main:app --reload

# noutro terminal WSL: coletor de SSH (se tiver auth.log real pra apontar)
python3 -c "from siem.collector import run_collector; run_collector('/var/log/auth.log', 'ssh')"

# sniffer de rede (precisa de sudo)
sudo python3 -c "from network.sniffer import run_sniffer; run_sniffer(interface='eth0')"
```

Abre `frontend/index.html` **no navegador do Windows** normalmente — ele
aponta pra `localhost:8000`, e o WSL2 expõe `localhost` compartilhado com
o Windows por padrão (não precisa configurar nada extra pra isso).

## 4. Limitação real da rede do WSL2 (leia antes de testar o sniffer)

Por padrão, a rede do WSL2 é **virtualizada/NAT** — uma rede própria,
separada do seu Wi-Fi/Ethernet físico. Isso significa:

- O sniffer **vai capturar** o que acontecer dentro do próprio WSL2
  (ex: você rodando `curl`/`nmap` de dentro dele contra ele mesmo, ou
  contra uma VM/container que também esteja na rede do WSL2).
- Ele **não vai ver** o tráfego do seu Wi-Fi físico nem de outros
  dispositivos da sua casa, a menos que você ative o modo
  **mirrored networking** (Windows 11 23H2+):

  Cria/edita `%UserProfile%\.wslconfig` no Windows:
  ```ini
  [wsl2]
  networkingMode=mirrored
  ```
  Depois `wsl --shutdown` no PowerShell e abre o WSL de novo.

Pro objetivo do projeto (testar contra Metasploitable2/Kali rodando como
VMs ou containers na mesma rede do WSL2), o modo NAT padrão já é
suficiente — não precisa mexer no `.wslconfig` a menos que queira
monitorar tráfego real da sua rede doméstica.

## 5. O que ainda não funciona mesmo dentro do WSL2

- **Resposta ativa (`ban_ip`)**: funciona normalmente, porque WSL2 tem
  `iptables` de verdade. Continua em `DRY_RUN=True` por padrão — mude
  isso só depois de entender o que `backend/response/active_response.py`
  faz.
- **Coletor de SSH**: só tem o que ler se existir um `auth.log` de
  verdade. Dentro do WSL2 puro, SSH geralmente não roda por padrão — ou
  você instala `openssh-server` no WSL (`sudo apt install openssh-server`)
  pra gerar logs reais, ou aponta o coletor pro log de uma VM/container
  separado (ex: Metasploitable2).
