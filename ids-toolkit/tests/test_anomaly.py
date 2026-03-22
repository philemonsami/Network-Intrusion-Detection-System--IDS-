import pytest
import time
from core.anomaly import AnomalyDetector

def test_anomaly_high_rate():
    detector = AnomalyDetector(rate_threshold=5, time_window=10)
    packet_info = {"src_ip": "192.168.1.100", "dst_port": 80}
    
    for _ in range(5):
        res = detector.detect(packet_info)
        assert res is None
        
    # the 6th packet triggered
    res = detector.detect(packet_info)
    assert res is not None
    assert res["type"] == "High Packet Rate"

def test_anomaly_port_scan():
    detector = AnomalyDetector(port_scan_threshold=3, time_window=10)
    
    for port in range(1, 4):
        packet_info = {"src_ip": "10.0.0.5", "dst_port": port}
        res = detector.detect(packet_info)
        assert res is None
        
    # the 4th unique port triggered
    packet_info = {"src_ip": "10.0.0.5", "dst_port": 4}
    res = detector.detect(packet_info)
    assert res is not None
    assert res["type"] == "Port Scan"
