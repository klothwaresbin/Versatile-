# 🛡️ Versatile — Advanced Network Traffic Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python Version" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License" />
  <img src="https://img.shields.io/badge/status-Active-brightgreen.svg" alt="Status" />
</p>

---

## 🎯 What is Versatile?

**Versatile** is a powerful, real-time and offline network traffic analyzer written in Python.  
It inspects PCAP files or live network interfaces to detect suspicious behaviors such as:

- SYN, FIN, NULL, Xmas scans  
- RST floods  
- UDP floods and port sweeps  
- ICMP floods and unusual ICMP types  
- Unusual port usage  
- Short-lived TCP connections (possible probes or scans)  

With rich color-coded console output, **Versatile** helps network admins and cybersecurity professionals quickly identify potential threats and anomalies in their networks.

---

## ✨ Features

- Supports **live capture** and **offline PCAP analysis**  
- Detects common network scanning and flooding attack patterns  
- Highlights unusual and suspicious port activities  
- Periodic live reporting with option for verbose output  
- Generates detailed, exportable reports in JSON or text formats  
- Clean, modern console UI powered by [rich](https://github.com/Textualize/rich)  
- Handles interrupt signals gracefully with final report generation  

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher  
- `pip` package manager  

### Install dependencies

```bash
pip install -r requirements.txt
```

*requirements.txt* includes:

```
scapy
rich
```

---

## 💻 Usage

### Command line options

```bash
usage: versatile.py [-h] [-f FILE] [-i INTERFACE] [-o OUTPUT] [-v] [-t INTERVAL]

Advanced PCAP Analyzer with live capture support

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Input PCAP file to analyze
  -i INTERFACE, --interface INTERFACE
                        Network interface for live capture
  -o OUTPUT, --output OUTPUT
                        Output report file (txt or json) (default: report.txt)
  -v, --verbose         Verbose output to console
  -t INTERVAL, --interval INTERVAL
                        Report interval in seconds for live capture (default: 10)
```

---

### Examples

- Analyze a PCAP file and save a text report:

```bash
python versatile.py -f capture.pcap -o analysis_report.txt
```

- Capture live traffic on interface `eth0` and print periodic reports (every 15 seconds):

```bash
python versatile.py -i eth0 -t 15
```

- Capture live traffic on `wlan0` with verbose console output and export JSON report:

```bash
python versatile.py -i wlan0 -v -o live_report.json
```

> **Note:** Press `Ctrl+C` during live capture to stop and save the final report.

---

## 🎨 Output Preview

![Sample Output](https://raw.githubusercontent.com/klothwaresbin/versatile/main/docs/sample_output.png)

*Example of colorful tables and summaries in the console powered by rich.*

---

## 🧩 How It Works

1. **Packet capture/reading:**  
   Captures live traffic or loads packets from a PCAP file.

2. **Packet inspection:**  
   Analyzes TCP, UDP, and ICMP packets, tracking flags, ports, and timing.

3. **Anomaly detection:**  
   Applies thresholds to detect suspicious behaviors like scans and floods.

4. **Reporting:**  
   Generates a clear, color-coded summary report in the console and exports results to a file.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check [issues page](https://github.com/klothwaresbin/versatile/issues).

---

## 🙌 Acknowledgements

- Built with [Scapy](https://scapy.net/) for packet processing  
- Powered by [Rich](https://github.com/Textualize/rich) for beautiful terminal output  

---

## 📞 Contact

Created by **Your Name** — [connor341wort@gmail.com](mailto:your.email@example.com)  
Follow me on [GitHub](https://github.com/klothwaresbin)

---

*Stay secure and keep your network versatile! 🛡️*
