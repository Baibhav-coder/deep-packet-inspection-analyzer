from collections import defaultdict

import matplotlib.pyplot as plt


class BandwidthStats:

    def __init__(self):

        self.bytes_by_app = defaultdict(int)
        self.packets_by_app = defaultdict(int)

    def update(self, app, size):

        name = app.name

        self.bytes_by_app[name] += size
        self.packets_by_app[name] += 1

    def get_rows(self):

        rows = []

        for app, bytes_ in sorted(
            self.bytes_by_app.items(),
            key=lambda x: x[1],
            reverse=True
        ):

            rows.append((app, self.packets_by_app[app], bytes_))

        return rows

    def generate_chart(self):

        apps = list(self.bytes_by_app.keys())
        values = list(self.bytes_by_app.values())

        if not apps:
            return

        plt.figure(figsize=(10, 5))

        plt.bar(apps, values)

        plt.xticks(rotation=45)

        plt.title("Bandwidth Usage by Application")
        plt.xlabel("Application")
        plt.ylabel("Bytes")

        plt.tight_layout()

        plt.savefig("bandwidth_by_app.png")
        plt.show()

        plt.close()

        print("\nBandwidth graph saved as bandwidth_by_app.png")