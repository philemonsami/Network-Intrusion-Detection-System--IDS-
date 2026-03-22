import time
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, rate_threshold=100, port_scan_threshold=15, time_window=10):
        self.rate_threshold = rate_threshold
        self.port_scan_threshold = port_scan_threshold
        self.time_window = time_window
        
        self.ip_packet_count = defaultdict(list)
        self.ip_ports_accessed = defaultdict(lambda: defaultdict(list))

    def _cleanup_old_records(self, current_time):
        for ip in list(self.ip_packet_count.keys()):
            self.ip_packet_count[ip] = [ts for ts in self.ip_packet_count[ip] if current_time - ts <= self.time_window]
            if not self.ip_packet_count[ip]:
                del self.ip_packet_count[ip]
                
        for ip in list(self.ip_ports_accessed.keys()):
            for port in list(self.ip_ports_accessed[ip].keys()):
                self.ip_ports_accessed[ip][port] = [ts for ts in self.ip_ports_accessed[ip][port] if current_time - ts <= self.time_window]
                if not self.ip_ports_accessed[ip][port]:
                    del self.ip_ports_accessed[ip][port]
            if not self.ip_ports_accessed[ip]:
                del self.ip_ports_accessed[ip]

    def detect(self, packet_info):
        """
        Detect anomalies. Returns an anomaly detection dict if found, else None.
        """
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        
        if not src_ip:
            return None

        current_time = time.time()
        self._cleanup_old_records(current_time)

        self.ip_packet_count[src_ip].append(current_time)
        if len(self.ip_packet_count[src_ip]) > self.rate_threshold:
            # i didnt  want it to alert infinitely, a better design might debounce this
            return {"type": "High Packet Rate", "severity": "HIGH", "detail": f"{len(self.ip_packet_count[src_ip])} pkts"}

        if dst_port:
            self.ip_ports_accessed[src_ip][dst_port].append(current_time)
            unique_ports = len(self.ip_ports_accessed[src_ip])
            if unique_ports > self.port_scan_threshold:
                return {"type": "Port Scan", "severity": "HIGH", "detail": f"Scanned {unique_ports} ports"}

        return None
