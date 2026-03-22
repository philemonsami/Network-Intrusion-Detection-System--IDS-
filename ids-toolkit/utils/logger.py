import json
import logging
from pathlib import Path

class AlertLogger:
    def __init__(self, log_file=None):
        if log_file is None:
            base_dir = Path(__file__).parent.parent
            log_file = base_dir / "data" / "alerts.log"
            
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger("IDS_Logger")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(self.log_file)
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def log_alert(self, event_data):
        self.logger.info(json.dumps(event_data))
