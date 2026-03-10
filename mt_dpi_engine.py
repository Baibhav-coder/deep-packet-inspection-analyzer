import threading

from pcap_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import SNIExtractor
from app_classifier import AppClassifier
from connection_tracker import ConnectionTracker
from traffic_stats import TrafficStats
from connection_stats import ConnectionStats
from fast_path import FastPathCache
from rule_engine import RuleEngine
from thread_safe_queue import ThreadSafeQueue
from load_balancer import LoadBalancer


class MultiThreadedDPIEngine:
    """
    Multi-threaded DPI engine that:
    - reads packets from pcap
    - load balances them to workers
    - uses fast path cache
    - applies rules
    - tracks connections and stats
    """

    def __init__(self, pcap_file: str, num_workers: int = 4):
        self.pcap_file = pcap_file
        self.num_workers = num_workers

        self.reader = PcapReader(pcap_file)
        self.parser = PacketParser()

        self.tracker = ConnectionTracker()
        self.traffic_stats = TrafficStats()
        self.connection_stats = ConnectionStats()
        self.fast_path = FastPathCache()
        self.rule_engine = RuleEngine()

        self.worker_queues = [ThreadSafeQueue() for _ in range(num_workers)]
        self.load_balancer = LoadBalancer(self.worker_queues)

        self.threads = []
        self.stop_signal = object()

    def configure_rules(self):
        """
        Add example rules here.
        """
        # self.rule_engine.block_app("TIKTOK")
        # self.rule_engine.block_domain("facebook")
        # self.rule_engine.block_ip("192.168.1.50")
        # self.rule_engine.monitor_app("YOUTUBE")
        pass

    def worker(self, worker_id: int):
        while True:
            item = self.worker_queues[worker_id].pop(timeout=1)

            if item is None:
                continue

            if item is self.stop_signal:
                break

            ts = item["ts"]
            raw_packet = item["raw_packet"]
            parsed = item["parsed"]

            cached_app = self.fast_path.get(parsed)

            if cached_app is not None:
                app = cached_app
                sni = None
            else:
                sni = SNIExtractor.extract_sni(parsed["payload"])
                app = AppClassifier.classify(parsed, sni)

                if app.name not in {"UNKNOWN", "HTTP", "HTTPS", "DNS"}:
                    self.fast_path.set(parsed, app)

            decision = self.rule_engine.decide(parsed, sni, app)

            parsed["size"] = len(raw_packet)
            parsed["decision"] = decision

            self.tracker.update(parsed, app)
            self.traffic_stats.update(len(raw_packet), app)

            print(
                f"[Worker {worker_id}] "
                f"{parsed['src_ip']} -> {parsed['dst_ip']} "
                f"{parsed['protocol']} {parsed['src_port']} -> {parsed['dst_port']} "
                f"| SNI: {sni} | APP: {app.name} | DECISION: {decision}"
            )

            self.worker_queues[worker_id].task_done()

    def run(self):
        self.configure_rules()

        for worker_id in range(self.num_workers):
            thread = threading.Thread(target=self.worker, args=(worker_id,))
            thread.start()
            self.threads.append(thread)

        for ts, raw_packet in self.reader.read_packets():
            parsed = self.parser.parse_packet(raw_packet)

            if parsed:
                item = {
                    "ts": ts,
                    "raw_packet": raw_packet,
                    "parsed": parsed,
                }
                self.load_balancer.dispatch(item)

        for queue in self.worker_queues:
            queue.push(self.stop_signal)

        for thread in self.threads:
            thread.join()

        self.tracker.print_summary()
        self.traffic_stats.print_summary()
        self.connection_stats.update_from_tracker(self.tracker)
        self.connection_stats.print_summary()