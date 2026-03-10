from collections import defaultdict


class TopTalkers:

    def __init__(self):

        self.bytes_by_ip = defaultdict(int)
        self.packets_by_ip = defaultdict(int)

        self.bytes_by_flow = defaultdict(int)
        self.packets_by_flow = defaultdict(int)

    def update(self, packet, size):

        src = packet["src_ip"]
        dst = packet["dst_ip"]

        self.bytes_by_ip[src] += size
        self.bytes_by_ip[dst] += size

        self.packets_by_ip[src] += 1
        self.packets_by_ip[dst] += 1

        flow = (
            packet["src_ip"],
            packet["dst_ip"],
            packet["src_port"],
            packet["dst_port"],
            packet["protocol"],
        )

        self.bytes_by_flow[flow] += size
        self.packets_by_flow[flow] += 1

    def get_top_ips(self, n=10):

        rows = []

        for ip, bytes_ in sorted(
            self.bytes_by_ip.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]:

            rows.append((ip, self.packets_by_ip[ip], bytes_))

        return rows

    def get_top_flows(self, n=10):

        rows = []

        for flow, bytes_ in sorted(
            self.bytes_by_flow.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]:

            src, dst, sp, dp, proto = flow

            rows.append((
                f"{src}:{sp}",
                f"{dst}:{dp}",
                proto,
                self.packets_by_flow[flow],
                bytes_
            ))

        return rows