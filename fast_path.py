class FastPathCache:
    """
    Stores already-classified flows so later packets
    can skip full DPI inspection.
    """

    def __init__(self):
        self.cache = {}

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

    def get(self, parsed_packet):
        key = self._make_key(parsed_packet)
        return self.cache.get(key)

    def set(self, parsed_packet, app):
        key = self._make_key(parsed_packet)
        self.cache[key] = app

    def contains(self, parsed_packet):
        key = self._make_key(parsed_packet)
        return key in self.cache

    def clear(self):
        self.cache.clear()