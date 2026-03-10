class LoadBalancer:
    """
    Distributes packets across worker queues based on flow hash,
    so packets from the same connection go to the same worker.
    """

    def __init__(self, worker_queues):
        self.worker_queues = worker_queues

    def _make_key(self, parsed_packet):
        forward = (
            parsed_packet["src_ip"],
            parsed_packet["dst_ip"],
            parsed_packet["src_port"],
            parsed_packet["dst_port"],
            parsed_packet["protocol"],
        )

        reverse = (
            parsed_packet["dst_ip"],
            parsed_packet["src_ip"],
            parsed_packet["dst_port"],
            parsed_packet["src_port"],
            parsed_packet["protocol"],
        )

        return min(forward, reverse)

    def dispatch(self, item):
        """
        item is expected to be:
        {
            "ts": ...,
            "raw_packet": ...,
            "parsed": ...
        }
        """
        parsed_packet = item["parsed"]
        key = self._make_key(parsed_packet)
        index = hash(key) % len(self.worker_queues)
        self.worker_queues[index].push(item)