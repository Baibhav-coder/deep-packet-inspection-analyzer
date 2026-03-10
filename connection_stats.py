from collections import defaultdict


class ConnectionStats:

    def __init__(self):
        self.allowed_counts = defaultdict(int)
        self.blocked_counts = defaultdict(int)

        self.total_connections = 0
        self.allowed_connections = 0
        self.blocked_connections = 0

    def update_from_tracker(self, tracker):

        self.allowed_counts.clear()
        self.blocked_counts.clear()

        self.total_connections = 0
        self.allowed_connections = 0
        self.blocked_connections = 0

        for _, data in tracker.connections.items():

            app_name = data["app"].name
            decision = data["decision"]

            self.total_connections += 1

            if decision == "BLOCK":
                self.blocked_counts[app_name] += 1
                self.blocked_connections += 1
            else:
                self.allowed_counts[app_name] += 1
                self.allowed_connections += 1

    def print_summary(self):

        print("\n===== CONNECTION STATISTICS =====\n")

        print("Total Connections:", self.total_connections)
        print("Allowed/Monitored Connections:", self.allowed_connections)
        print("Blocked Connections:", self.blocked_connections)

        print("\nAllowed/Monitored Connections by Application:\n")

        for app_name, count in sorted(
            self.allowed_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            print(f"{app_name}: {count}")

        print("\nBlocked Connections by Application:\n")

        if not self.blocked_counts:
            print("None")
        else:
            for app_name, count in sorted(
                self.blocked_counts.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                print(f"{app_name}: {count}")