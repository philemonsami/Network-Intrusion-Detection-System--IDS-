from core.signatures import SignatureMatcher
from core.anomaly import AnomalyDetector
from utils.logger import AlertLogger
import time

class Analyzer:
    def __init__(self, callback=None):
        self.signature_matcher = SignatureMatcher()
        self.anomaly_detector = AnomalyDetector()
        self.logger = AlertLogger()
        self.callback = callback

    def analyze(self, packet_info):
        sig_result = self.signature_matcher.match(packet_info)
        if sig_result:
            self.create_alert(packet_info, sig_result)

        anomaly_result = self.anomaly_detector.detect(packet_info)
        if anomaly_result:
            self.create_alert(packet_info, anomaly_result)

    def create_alert(self, packet_info, detection_result):
        event = {
            "timestamp": time.time(),
            "src_ip": packet_info.get('src_ip'),
            "dst_ip": packet_info.get('dst_ip'),
            "threat_type": detection_result.get("type"),
            "severity": detection_result.get("severity"),
            "detail": detection_result.get("detail")
        }
        
        self.logger.log_alert(event)
        
        if self.callback:
            self.callback(event)
