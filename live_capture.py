from scapy.all import sniff, Ether
import socket

from sni_extractor import SNIExtractor
from app_classifier import AppClassifier


class LiveCapture:
    """
    Live packet capture using scapy.
    Note:
    - usually needs admin privileges
    - requires: pip install scapy
    """

    def __init__(self, interface=None, packet_count=20):
        self.interface = interface
        self.packet_count = packet_count

    def parse_live_packet(self, packet):
        try:
            if not packet.haslayer("IP"):
                return None

            ip = packet["IP"]
            src_ip = ip.src
            dst_ip = ip.dst

            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                payload = bytes(tcp.payload)

                parsed = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "protocol": "TCP",
                    "payload": payload,
                }

                sni = SNIExtractor.extract_sni(payload)
                app = AppClassifier.classify(parsed, sni)

                print(
                    parsed["src_ip"],
                    "->",
                    parsed["dst_ip"],
                    parsed["protocol"],
                    parsed["src_port"],
                    "->",
                    parsed["dst_port"],
                    "| SNI:",
                    sni,
                    "| APP:",
                    app.name,
                )

            elif packet.haslayer("UDP"):
                udp = packet["UDP"]

                parsed = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "protocol": "UDP",
                    "payload": bytes(udp.payload),
                }

                app = AppClassifier.classify(parsed, None)

                print(
                    parsed["src_ip"],
                    "->",
                    parsed["dst_ip"],
                    parsed["protocol"],
                    parsed["src_port"],
                    "->",
                    parsed["dst_port"],
                    "| SNI: None | APP:",
                    app.name,
                )

        except Exception:
            return None

    def run(self):
        sniff(
            iface=self.interface,
            prn=self.parse_live_packet,
            store=False,
            count=self.packet_count,
        )