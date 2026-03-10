import dpkt
import socket


class PacketParser:
    def parse_packet(self, raw_packet: bytes):
        try:
            eth = dpkt.ethernet.Ethernet(raw_packet)

            if not isinstance(eth.data, dpkt.ip.IP):
                return None

            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "protocol": "TCP",
                    "payload": tcp.data,
                }

            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "protocol": "UDP",
                    "payload": udp.data,
                }

            return None

        except Exception:
            return None