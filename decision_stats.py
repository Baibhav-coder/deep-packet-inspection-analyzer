from collections import defaultdict


class DecisionStats:
    """
    Tracks ALLOW / BLOCK / MONITOR decisions.
    """

    def __init__(self):
        self.counts = defaultdict(int)

    def update(self, decision: str):
        self.counts[decision] += 1

    def print_summary(self):
        print("\n===== DECISION STATISTICS =====\n")

        for decision in ["ALLOW", "BLOCK", "MONITOR"]:
            print(f"{decision}: {self.counts.get(decision, 0)}")