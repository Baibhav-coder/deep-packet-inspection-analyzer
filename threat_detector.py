class ThreatDetector:

    def __init__(self):

        self.alerts = []

        self.suspicious_ports = {
            23,
            2323,
            4444,
            1337,
            6667,
            31337
        }

        self.malware_keywords = {
            "malware",
            "phishing",
            "trojan",
            "ransom",
            "botnet",
            "c2"
        }

    def inspect_packet(self, packet, sni, app, decision):

        src = packet["src_ip"]
        dst = packet["dst_ip"]

        sp = packet["src_port"]
        dp = packet["dst_port"]

        if sp in self.suspicious_ports or dp in self.suspicious_ports:

            self.alerts.append((
                "HIGH",
                "Suspicious Port",
                f"{src}:{sp} -> {dst}:{dp}"
            ))

        if sni:

            sni = sni.lower()

            for keyword in self.malware_keywords:

                if keyword in sni:

                    self.alerts.append((
                        "HIGH",
                        "Malware Domain",
                        sni
                    ))

        if decision == "BLOCK":

            self.alerts.append((
                "MEDIUM",
                "Blocked Traffic",
                f"{src} -> {dst}"
            ))

    def get_alert_rows(self):

        return self.alerts