# Versatile-
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
