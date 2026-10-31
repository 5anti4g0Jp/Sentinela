"""
Módulo "mini-Wireshark" — captura e inspeciona pacotes ao vivo, alimentando
o mesmo pipeline de Events que o SIEM usa (assim a detecção enxerga tráfego
de rede e logs pela mesma lente).

ATENÇÃO: só rode isso em interface que você tem autorização para monitorar
(sua VM/lab). Requer privilégio (root / CAP_NET_RAW) e a lib `scapy`.
"""
from datetime import datetime, timezone

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR  # type: ignore
except ImportError:  # scapy pode não estar instalado no ambiente de dev
    sniff = IP = TCP = UDP = DNS = DNSQR = None

from db import SessionLocal, Event


def _utcnow():
    return datetime.now(timezone.utc)


def _classify_tcp_flags(flags: int) -> str:
    # bits: FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
    if flags & 0x02 and not flags & 0x10:
        return "tcp_syn"       # SYN sem ACK = tentativa de conexão / scan
    if flags & 0x04:
        return "tcp_rst"
    if flags & 0x01:
        return "tcp_fin"
    return "tcp_other"


def _handle_packet(pkt, pcap_writer=None):
    if pcap_writer is not None:
        pcap_writer.write(pkt)

    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    action = "ip_packet"
    dst_port = None

    if TCP in pkt:
        dst_port = int(pkt[TCP].dport)
        action = _classify_tcp_flags(int(pkt[TCP].flags))
    elif UDP in pkt:
        dst_port = int(pkt[UDP].dport)
        action = "udp_packet"
        if DNS in pkt and pkt.haslayer(DNSQR):
            action = "dns_query"

    db = SessionLocal()
    try:
        db.add(Event(
            timestamp=_utcnow(), source="network", src_ip=src_ip, dst_ip=dst_ip,
            dst_port=dst_port, action=action, raw=pkt.summary(),
        ))
        db.commit()
    finally:
        db.close()


def run_sniffer(interface: str = None, save_pcap: str = None, bpf_filter: str = None):
    """
    Captura pacotes ao vivo e grava Events normalizados.

    interface: nome da interface (ex: "eth0"). None = interface padrão.
    save_pcap: caminho opcional para salvar a captura em .pcap
               (abrível depois no Wireshark de verdade).
    bpf_filter: filtro BPF opcional, ex: "tcp or udp" para ignorar outros protocolos.
    """
    if sniff is None:
        raise RuntimeError(
            "scapy não está instalado. Rode: pip install scapy "
            "(e execute este processo como root / com CAP_NET_RAW)."
        )

    pcap_writer = None
    if save_pcap:
        from scapy.utils import PcapWriter
        pcap_writer = PcapWriter(save_pcap, append=True, sync=True)

    # Filtro BPF exige libpcap instalada no sistema (apt install libpcap0.8
    # no Debian/Ubuntu). Sem ela, sniff() com `filter=` falha e scapy só
    # imprime um aviso no console — sem exceção, sem captura, sem erro
    # óbvio. Em vez de deixar isso falhar calado, testamos antes e caímos
    # pra captura sem filtro (mais eventos chegam, mas _handle_packet já
    # filtra por camada IP/TCP/UDP, então a classificação continua correta).
    use_filter = bpf_filter or "tcp or udp"
    try:
        from scapy.arch.common import compile_filter
        # linktype=1 (DLT_EN10MB/Ethernet) só pra testar se libpcap resolve o
        # filtro sem precisar de uma interface ao vivo nesse ponto do código.
        compile_filter(use_filter, linktype=1)
    except Exception:
        print(
            "[sentinela] AVISO: libpcap indisponível — capturando sem filtro BPF "
            "(mais lento, mas não falha silenciosamente). "
            "Instale libpcap0.8 pra capturar com filtro."
        )
        use_filter = None

    sniff(
        iface=interface,
        filter=use_filter,
        prn=lambda pkt: _handle_packet(pkt, pcap_writer),
        store=False,  # não acumula pacotes em memória — grava e descarta
    )
