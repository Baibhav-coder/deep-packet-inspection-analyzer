import dpkt
from typing import Generator, Tuple


class PcapReader:
    """
    Reads packets from a PCAP file
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    def read_packets(self) -> Generator[Tuple[float, bytes], None, None]:
        """
        Generator that yields packets from the PCAP file
        """
        with open(self.file_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                yield timestamp, buf