from collections import defaultdict


class TrafficStats:

    def __init__(self):
        self.app_counts = defaultdict(int)
        self.total_packets = 0
        self.total_bytes = 0

    def update(self, packet_size, app):
        self.total_packets += 1
        self.total_bytes += packet_size
        self.app_counts[app.name] += 1

    def print_summary(self):

        print("\n===== TRAFFIC STATISTICS =====\n")

        print("Total Packets:", self.total_packets)
        print("Total Bytes:", self.total_bytes)

        print("\nPackets by Application:\n")

        for app, count in sorted(
            self.app_counts.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            print(f"{app}: {count}")