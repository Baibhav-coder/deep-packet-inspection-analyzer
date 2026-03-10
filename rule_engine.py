class RuleEngine:

    def __init__(self):
        self.blocked_ports = set()
        self.blocked_apps = set()
        self.blocked_ips = set()
        self.blocked_domains = set()

    def block_port(self, port):
        self.blocked_ports.add(port)

    def block_app(self, app):
        self.blocked_apps.add(app.upper())

    def block_ip(self, ip):
        self.blocked_ips.add(ip)

    def block_domain(self, domain):
        self.blocked_domains.add(domain.lower())

    def decide(self, parsed_packet, sni, app):

        src_ip = parsed_packet["src_ip"]
        dst_ip = parsed_packet["dst_ip"]
        src_port = parsed_packet["src_port"]
        dst_port = parsed_packet["dst_port"]

        if src_port in self.blocked_ports or dst_port in self.blocked_ports:
            return "BLOCK"

        if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
            return "BLOCK"

        if sni:
            sni = sni.lower()
            for domain in self.blocked_domains:
                if domain in sni:
                    return "BLOCK"

        if app.name.upper() in self.blocked_apps:
            return "BLOCK"

        return "ALLOW"