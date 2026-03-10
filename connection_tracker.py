from dpi_types import AppType


class ConnectionTracker:
    """
    Tracks network flows and stores the final decision for each flow.
    """

    def __init__(self):
        self.connections = {}

    def get_key(self, packet):
        forward = (
            packet["src_ip"],
            packet["dst_ip"],
            packet["src_port"],
            packet["dst_port"],
            packet["protocol"],
        )

        reverse = (
            packet["dst_ip"],
            packet["src_ip"],
            packet["dst_port"],
            packet["src_port"],
            packet["protocol"],
        )

        return min(forward, reverse)

    def update(self, packet, app, decision):
        key = self.get_key(packet)

        if key not in self.connections:
            self.connections[key] = {
                "packets": 0,
                "bytes": 0,
                "app": app,
                "decision": decision,
            }

        self.connections[key]["packets"] += 1
        self.connections[key]["bytes"] += packet["size"]

        current_app = self.connections[key]["app"]
        current_decision = self.connections[key]["decision"]

        generic_apps = {
            AppType.UNKNOWN,
            AppType.HTTP,
            AppType.HTTPS,
            AppType.DNS,
        }

        if current_app in generic_apps and app not in generic_apps:
            self.connections[key]["app"] = app

        if current_decision == "ALLOW" and decision in {"MONITOR", "BLOCK"}:
            self.connections[key]["decision"] = decision
        elif current_decision == "MONITOR" and decision == "BLOCK":
            self.connections[key]["decision"] = decision

    def print_summary(self):
        print("\n==== ALLOWED / MONITORED CONNECTIONS ====\n")

        for key, data in self.connections.items():
            if data["decision"] == "BLOCK":
                continue

            src_ip, dst_ip, src_port, dst_port, proto = key

            print(
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"| {proto} | APP: {data['app'].name} "
                f"| DECISION: {data['decision']} "
                f"| Packets: {data['packets']} "
                f"| Bytes: {data['bytes']}"
            )

    def print_blocked_summary(self):
        print("\n==== BLOCKED CONNECTIONS ====\n")

        blocked_found = False

        for key, data in self.connections.items():
            if data["decision"] != "BLOCK":
                continue

            blocked_found = True

            src_ip, dst_ip, src_port, dst_port, proto = key

            print(
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"| {proto} | APP: {data['app'].name} "
                f"| DECISION: {data['decision']} "
                f"| Packets: {data['packets']} "
                f"| Bytes: {data['bytes']}"
            )

        if not blocked_found:
            print("No blocked connections.")