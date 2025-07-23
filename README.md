# Versatile-
Tool Description

Advanced Network Traffic Analyzer with Real-Time and PCAP Support

This Python-based tool is designed to analyze network traffic data captured either from live network interfaces or from pre-recorded PCAP files. It inspects packets at a granular level to detect a variety of suspicious and anomalous network behaviors that could indicate malicious activity or network misuse.

Key features include:

    Comprehensive Protocol Analysis: Supports in-depth inspection of TCP, UDP, and ICMP protocols to identify unusual patterns such as scan attempts, flood attacks, and abnormal flag usage.

    Suspicious Behavior Detection: Automatically flags common reconnaissance and attack techniques, including SYN scans, FIN scans, NULL scans, Xmas scans, RST floods, UDP floods, UDP port sweeps, and ICMP floods.

    Unusual Port Activity Monitoring: Detects connections involving uncommon or suspicious source and destination ports outside of typical well-known services.

    Short-Lived TCP Connections Identification: Highlights TCP connections that are established and closed rapidly, which can be an indicator of scanning or probing.

    Real-Time and Offline Analysis: Capable of processing live network traffic from a specified network interface with periodic reporting, or analyzing offline PCAP files with detailed summary reports.

    Clear and Colorful Console Output: Utilizes a modern, colorful, and easy-to-read console interface using the rich library, displaying findings in organized tables with clear headings for quick assessment.

    Exportable Reports: Allows exporting analysis results to JSON or plain text files for record-keeping, further investigation, or sharing with others.

    Interrupt Handling: Gracefully stops live capture upon user interruption (Ctrl+C), immediately generating and saving a final comprehensive report.

This tool is ideal for network administrators, security analysts, and cybersecurity enthusiasts who want a lightweight yet powerful utility to quickly detect suspicious network behaviors and potential attacks in real-time or through offline traffic analysis.
