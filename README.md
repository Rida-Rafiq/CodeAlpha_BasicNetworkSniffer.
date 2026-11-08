
# Basic Network Sniffer

A Python-based network packet sniffer using `scapy` to capture and analyze network traffic.

## Requirements
- Python 3.x
- Scapy (`pip install scapy`)
- Npcap (Windows) or libpcap (Linux/macOS)

## Usage
Run the script with Administrator or root privileges:
`sudo python network_sniffer.py -c 20`

**Arguments:**
- `-i` or `--interface`: Specify the network interface (e.g., eth0, wlan0).
- `-c` or `--count`: Number of packets to capture (default is 10).
