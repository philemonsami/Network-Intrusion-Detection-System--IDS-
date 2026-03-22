import threading
from scapy.all import sniff, IP, TCP, UDP
from core.analyzer import Analyzer

class PacketSniffer:
    def __init__(self, interface=None, analyzer=None):
        self.interface = interface
        self.analyzer = analyzer or Analyzer()
        self.running = False

    def start(self):
        self.running = True
       
        self.thread = threading.Thread(target=self._sniff_loop)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False

    def _sniff_loop(self):
        
        sniff(iface=self.interface, prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)

    def process_packet(self, packet):
        if not self.running:
            return

        packet_info = {
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'payload': None
        }

        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto

        if TCP in packet:
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['payload'] = bytes(packet[TCP].payload)
        elif UDP in packet:
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            packet_info['payload'] = bytes(packet[UDP].payload)

     
        self.analyzer.analyze(packet_info)
