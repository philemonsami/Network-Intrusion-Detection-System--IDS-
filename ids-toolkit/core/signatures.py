import json
import hashlib
from pathlib import Path

class SignatureMatcher:
    def __init__(self, signatures_file=None):
        if signatures_file is None:
           
            base_dir = Path(__file__).parent.parent
            signatures_file = base_dir / "data" / "signatures.json"
        
        self.signatures = self._load_signatures(signatures_file)

    def _load_signatures(self, file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
           
            return {
                "malicious_ips": [],
                "suspicious_ports": [],
                "payload_hashes": []
            }

    def match(self, packet_info):
        """
        Returns a detection result dict if a signature matches, else None.
        """
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        payload = packet_info.get('payload')

        for mal_ip in self.signatures.get("malicious_ips", []):
            if src_ip == mal_ip or dst_ip == mal_ip:
                return {"type": "Malicious IP", "severity": "HIGH", "detail": mal_ip}

        suspicious_ports = self.signatures.get("suspicious_ports", [])
        if src_port in suspicious_ports or dst_port in suspicious_ports:
            return {"type": "Suspicious Port", "severity": "MEDIUM", "detail": str(dst_port or src_port)}

        if payload:
            payload_hash = hashlib.md5(payload).hexdigest()
            if payload_hash in self.signatures.get("payload_hashes", []):
                return {"type": "Malicious Payload", "severity": "CRITICAL", "detail": payload_hash}

        return None
