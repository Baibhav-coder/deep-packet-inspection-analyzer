from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def build_demo_pcap(output_file="demo_threat.pcap"):
    packets = []

    # Normal HTTPS traffic
    packets.append(
        Ether() /
        IP(src="192.168.1.100", dst="142.250.185.206") /
        TCP(sport=54552, dport=443, flags="PA") /
        Raw(load=b"normal https traffic")
    )

    # Normal DNS traffic
    packets.append(
        Ether() /
        IP(src="192.168.1.100", dst="8.8.8.8") /
        UDP(sport=55178, dport=53) /
        Raw(load=b"dns query")
    )

    # Suspicious trojan-like traffic
    packets.append(
        Ether() /
        IP(src="192.168.1.100", dst="10.10.10.50") /
        TCP(sport=50001, dport=4444, flags="PA") /
        Raw(load=b"trojan command control")
    )

    # Response from suspicious server
    packets.append(
        Ether() /
        IP(src="10.10.10.50", dst="192.168.1.100") /
        TCP(sport=4444, dport=50001, flags="PA") /
        Raw(load=b"c2 response")
    )

    wrpcap(output_file, packets)
    print("Demo threat PCAP created:", output_file)


if __name__ == "__main__":
    build_demo_pcap()