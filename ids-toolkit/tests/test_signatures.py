import pytest
import tempfile
import json
from core.signatures import SignatureMatcher

def test_signature_matcher_ip():
    # i created dummy signatures
    sigs = {
        "malicious_ips": ["1.2.3.4"],
        "suspicious_ports": [],
        "payload_hashes": []
    }
    
    with tempfile.NamedTemporaryFile('w', delete=False) as f:
        json.dump(sigs, f)
        temp_path = f.name
        
    matcher = SignatureMatcher(signatures_file=temp_path)
    
    # Tested the match
    packet_info = {"src_ip": "1.2.3.4", "dst_ip": "8.8.8.8", "payload": None}
    res = matcher.match(packet_info)
    assert res is not None
    assert res["type"] == "Malicious IP"
    assert res["severity"] == "HIGH"

def test_signature_matcher_port():
    sigs = {
        "malicious_ips": [],
        "suspicious_ports": [4444],
        "payload_hashes": []
    }
    with tempfile.NamedTemporaryFile('w', delete=False) as f:
        json.dump(sigs, f)
        temp_path = f.name
        
    matcher = SignatureMatcher(signatures_file=temp_path)
    packet_info = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "src_port": 1234, "dst_port": 4444, "payload": None}
    res = matcher.match(packet_info)
    assert res is not None
    assert res["type"] == "Suspicious Port"
