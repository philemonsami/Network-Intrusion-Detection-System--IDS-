import pytest
from core.sniffer import PacketSniffer
from scapy.all import IP, TCP

class DummyAnalyzer:
    def __init__(self):
        self.analyzed_packets = []
        
    def analyze(self, packet_info):
        self.analyzed_packets.append(packet_info)

def test_packet_sniffer_process_packet():
    analyzer = DummyAnalyzer()
    sniffer = PacketSniffer(analyzer=analyzer)
    sniffer.running = True

    # i craeted dummy scapy packet
    pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    
    sniffer.process_packet(pkt)
    
    assert len(analyzer.analyzed_packets) == 1
    info = analyzer.analyzed_packets[0]
    assert info['src_ip'] == "192.168.1.1"
    assert info['dst_ip'] == "10.0.0.1"
    assert info['src_port'] == 12345
    assert info['dst_port'] == 80

def test_packet_sniffer_filtering():
    analyzer = DummyAnalyzer()
    sniffer = PacketSniffer(analyzer=analyzer)
    sniffer.running = False
    
    pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
    sniffer.process_packet(pkt)
    
    assert len(analyzer.analyzed_packets) == 0
