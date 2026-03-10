import tkinter as tk
from tkinter import filedialog

from connection_tracker import ConnectionTracker
from traffic_stats import TrafficStats
from connection_stats import ConnectionStats
from decision_stats import DecisionStats
from bandwidth_stats import BandwidthStats
from top_talkers import TopTalkers
from threat_detector import ThreatDetector
from ui_helpers import print_title, print_section, print_table

from pcap_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import SNIExtractor
from app_classifier import AppClassifier
from fast_path import FastPathCache
from rule_engine import RuleEngine

from output_writer import OutputWriter


SHOW_PACKET_LOGS = False


def choose_pcap_file():
    root = tk.Tk()
    root.withdraw()

    return filedialog.askopenfilename(
        title="Select PCAP File",
        filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
    )


pcap_file = choose_pcap_file()

if not pcap_file:
    print("No PCAP selected.")
    exit()

print("\nSelected PCAP:", pcap_file, "\n")


reader = PcapReader(pcap_file)
parser = PacketParser()

tracker = ConnectionTracker()
traffic_stats = TrafficStats()
connection_stats = ConnectionStats()
decision_stats = DecisionStats()
bandwidth_stats = BandwidthStats()
top_talkers = TopTalkers()
threat_detector = ThreatDetector()
fast_path = FastPathCache()
rule_engine = RuleEngine()

# OUTPUT WRITER (creates filtered PCAPs)
writer = OutputWriter("allowed_output.pcap", "blocked_output.pcap")

# BLOCK TROJAN PORT
rule_engine.block_port(4444)


for ts, raw_packet in reader.read_packets():

    parsed = parser.parse_packet(raw_packet)

    if not parsed:
        continue

    cached = fast_path.get(parsed)

    if cached:
        app = cached
        sni = None
    else:
        sni = SNIExtractor.extract_sni(parsed["payload"])
        app = AppClassifier.classify(parsed, sni)

        if app.name not in {"UNKNOWN", "HTTP", "HTTPS", "DNS"}:
            fast_path.set(parsed, app)

    decision = rule_engine.decide(parsed, sni, app)

    parsed["size"] = len(raw_packet)

    tracker.update(parsed, app, decision)
    traffic_stats.update(len(raw_packet), app)
    bandwidth_stats.update(app, len(raw_packet))
    top_talkers.update(parsed, len(raw_packet))
    threat_detector.inspect_packet(parsed, sni, app, decision)
    decision_stats.update(decision)

    # WRITE PACKETS INTO OUTPUT PCAPS
    writer.write(ts, raw_packet, decision)

    if SHOW_PACKET_LOGS:
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
            "| DECISION:",
            decision,
        )


connection_stats.update_from_tracker(tracker)

# CLOSE PCAP WRITERS
writer.close()

print_title("DEEP PACKET INSPECTION REPORT")


print_section("ALLOWED / MONITORED CONNECTIONS")

allowed_rows = []

for key, data in tracker.connections.items():

    if data["decision"] == "BLOCK":
        continue

    src_ip, dst_ip, src_port, dst_port, proto = key

    allowed_rows.append((
        f"{src_ip}:{src_port}",
        f"{dst_ip}:{dst_port}",
        proto,
        data["app"].name,
        data["decision"],
        data["packets"],
        data["bytes"],
    ))

print_table(
    ["Source", "Destination", "Proto", "App", "Decision", "Packets", "Bytes"],
    allowed_rows
)


print_section("BLOCKED CONNECTIONS")

blocked_rows = []

for key, data in tracker.connections.items():

    if data["decision"] != "BLOCK":
        continue

    src_ip, dst_ip, src_port, dst_port, proto = key

    blocked_rows.append((
        f"{src_ip}:{src_port}",
        f"{dst_ip}:{dst_port}",
        proto,
        data["app"].name,
        data["decision"],
        data["packets"],
        data["bytes"],
    ))

print_table(
    ["Source", "Destination", "Proto", "App", "Decision", "Packets", "Bytes"],
    blocked_rows
)


print_section("TRAFFIC STATISTICS")

print_table(
    ["Metric", "Value"],
    [
        ("Total Packets", traffic_stats.total_packets),
        ("Total Bytes", traffic_stats.total_bytes),
    ]
)


print_section("CONNECTION STATISTICS")

print_table(
    ["Metric", "Value"],
    [
        ("Total Connections", connection_stats.total_connections),
        ("Allowed/Monitored Connections", connection_stats.allowed_connections),
        ("Blocked Connections", connection_stats.blocked_connections),
    ]
)


print_section("DECISION STATISTICS")

print_table(
    ["Decision", "Count"],
    [
        ("ALLOW", decision_stats.counts.get("ALLOW", 0)),
        ("BLOCK", decision_stats.counts.get("BLOCK", 0)),
        ("MONITOR", decision_stats.counts.get("MONITOR", 0)),
    ]
)


print_section("TOP TALKERS")

print_table(
    ["IP Address", "Packets", "Bytes"],
    top_talkers.get_top_ips(10)
)


print_section("THREAT ALERTS")

print_table(
    ["Severity", "Type", "Details"],
    threat_detector.get_alert_rows()
)


print_section("BANDWIDTH BY APPLICATION")

print_table(
    ["Application", "Packets", "Bytes"],
    bandwidth_stats.get_rows()
)


bandwidth_stats.generate_chart()

print("\nAllowed packets saved to: allowed_output.pcap")
print("Blocked packets saved to: blocked_output.pcap")