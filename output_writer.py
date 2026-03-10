import dpkt


class OutputWriter:

    def __init__(self,
                 allowed_file="allowed_output.pcap",
                 blocked_file="blocked_output.pcap"):

        self.allowed_file = allowed_file
        self.blocked_file = blocked_file

        self.allowed_fp = open(self.allowed_file, "wb")
        self.blocked_fp = open(self.blocked_file, "wb")

        self.allowed_writer = dpkt.pcap.Writer(self.allowed_fp)
        self.blocked_writer = dpkt.pcap.Writer(self.blocked_fp)

    def write(self, ts, raw_packet, decision):

        if decision == "BLOCK":
            self.blocked_writer.writepkt(raw_packet, ts=ts)
        else:
            self.allowed_writer.writepkt(raw_packet, ts=ts)

    def close(self):
        self.allowed_fp.close()
        self.blocked_fp.close()