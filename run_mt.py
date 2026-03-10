from mt_dpi_engine import MultiThreadedDPIEngine

engine = MultiThreadedDPIEngine("test_dpi.pcap", num_workers=4)
engine.run()