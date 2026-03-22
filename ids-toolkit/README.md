# Samuel Network Intrusion Detection System (IDS)

## Overview
Samuel Network Intrusion Detection System (IDS) is a lightweight, Python-based security tool crafted for real-time network monitoring. It rapidly identifies suspicious network activities by combining signature-based detection with baseline anomaly detection, keeping you a step ahead of possible threats.

## Features
- **Packet Sniffing**: Uses `scapy` to analyze layer 3 and layer 4 network traffic in real time.
- **Signature-Based Detection**: Checks live traffic against known malicious signatures such as bad IPs, suspicious ports, and malicious payload hashes.
- **Anomaly Detection**: Monitors network behavior to identify irregular traffic patterns such as abrupt high packet rate floods and port scanning.
- **Alert Logging**: Persists alerts in JSON format for easy ingestion by SIEM tools or analysis pipelines.
- **Live Interactive Dashboard**: Leverages `rich` to present an interactive live feed of threat events directly in the CLI.

## Folder Structure
```text
ids-toolkit/
├── core/
│   ├── sniffer.py        # Core scapy packet interception
│   ├── signatures.py     # Signature-matching logic
│   ├── anomaly.py        # Behavior-based anomaly tracking 
│   └── analyzer.py       # Engine linking components together
│
├── utils/
│   ├── logger.py         # Disk-based alert storage
│   └── colors.py         # Standardized CLI color schemes
│
├── data/
│   ├── signatures.json   # Known threats database
│   └── alerts.log        # Threat logs output
│
├── cli/
│   ├── dashboard.py      # Rich live interactive UI loop
│   └── start.py          # Application entrypoint
│
├── tests/
│   ├── test_sniffer.py
│   ├── test_signatures.py
│   └── test_anomaly.py
│
├── requirements.txt
└── README.md
```

## How It Works
1. `cli/start.py` initializes a background `PacketSniffer` thread while firing up a Rich-powered console `Dashboard`.
2. The `PacketSniffer` invokes `scapy`'s `sniff` loop, unwrapping TCP/UDP IP packets into actionable dictionary payloads.
3. Every captured packet is immediately relayed to the `Analyzer`.
4. The `Analyzer` runs the packet through both the `SignatureMatcher` and `AnomalyDetector`.
5. If a detection fires, a standardized event object is logged using `AlertLogger` and visually pushed to the frontend `Dashboard`.

## Installation
Ensure you have Python 3.10+ installed.

1. Clone or navigate into the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. To safely sniff traffic across varied platforms, running this application in an administrative prompt or via `sudo` may be required depending on network interfaces.

## Usage
Run the CLI starting point:
```bash
python cli/start.py --interface eth0
```
*(If no interface is specified, scapy will fall back to resolving your default gateway)*

You can view available flags via:
```bash
python cli/start.py --help
```

## Example Alerts
```json
{"timestamp": 1696580983.3, "src_ip": "198.51.100.23", "dst_ip": "192.168.1.10", "threat_type": "Malicious IP", "severity": "HIGH", "detail": "198.51.100.23"}
{"timestamp": 1696581023.2, "src_ip": "10.0.0.5", "dst_ip": "192.168.1.5", "threat_type": "Port Scan", "severity": "HIGH", "detail": "Scanned 16 ports"}
```

## Future Plans
- Expand `signatures.json` integration to pull regular malware updates from OSINT blacklists.
- Enhance anomaly models to utilize statistical entropy for identifying encrypted shell tunnels.
- Deploy a web API module around the `alerts.log` to stream events remotely.
