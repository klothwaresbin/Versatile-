import argparse
import json
import signal
import sys
import threading
import time
from collections import defaultdict
from scapy.all import rdpcap, sniff, TCP, UDP, ICMP, IP

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

COMMON_PORTS = {80, 443, 53, 22, 21, 25, 110, 995, 143, 993, 3389, 5900}

def print_banner():
    banner_text = r"""
____   ____                           __  .__.__           
\   \ /   /___________  ___________ _/  |_|__|  |   ____   
 \   Y   // __ \_  __ \/  ___/\__  \\   __\  |  | _/ __ \  
  \     /\  ___/|  | \/\___ \  / __ \|  | |  |  |_\  ___/  
   \___/  \___  >__|  /____  >(____  /__| |__|____/\___  > 
              \/           \/      \/                  \/  


"""
    colored_banner = Text(banner_text, style="bold cyan")
    console.print(colored_banner)

class Analyzer:
    def __init__(self, verbose=False, report_interval=10):
        self.verbose = verbose
        self.report_interval = report_interval

        self.syn_packets = defaultdict(int)
        self.fin_packets = defaultdict(int)
        self.null_packets = defaultdict(int)
        self.xmas_packets = defaultdict(int)
        self.rst_packets = defaultdict(int)
        self.zero_payload_tcp = 0

        self.tcp_connection_times = defaultdict(list)
        self.unusual_ports = defaultdict(int)

        self.udp_flood = defaultdict(int)
        self.udp_ports_per_ip = defaultdict(set)

        self.icmp_types_count = defaultdict(lambda: defaultdict(int))

        self.total_packets = 0
        self.lock = threading.Lock()

        self.running = True

    def process_packet(self, pkt):
        if IP not in pkt:
            return

        with self.lock:
            self.total_packets += 1

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if TCP in pkt:
                tcp_layer = pkt[TCP]
                flags = tcp_layer.flags

                if flags & 0x02 and not (flags & 0x10):
                    self.syn_packets[(src_ip, tcp_layer.sport)] += 1

                if flags & 0x01 and not (flags & 0x10):
                    self.fin_packets[(src_ip, tcp_layer.sport)] += 1

                if flags == 0:
                    self.null_packets[(src_ip, tcp_layer.sport)] += 1

                if flags & 0x29 == 0x29:
                    self.xmas_packets[(src_ip, tcp_layer.sport)] += 1

                if flags & 0x04:
                    self.rst_packets[(src_ip, tcp_layer.sport)] += 1

                if len(tcp_layer.payload) == 0:
                    self.zero_payload_tcp += 1

                if hasattr(pkt, "time"):
                    key = (src_ip, dst_ip)
                    self.tcp_connection_times[key].append(pkt.time)

                if (tcp_layer.sport not in COMMON_PORTS and tcp_layer.sport > 1024) or \
                   (tcp_layer.dport not in COMMON_PORTS and tcp_layer.dport > 1024):
                    self.unusual_ports[(src_ip, tcp_layer.sport, tcp_layer.dport)] += 1

            elif UDP in pkt:
                udp_layer = pkt[UDP]
                self.udp_flood[(src_ip, udp_layer.dport)] += 1
                self.udp_ports_per_ip[src_ip].add(udp_layer.dport)

                if (udp_layer.sport not in COMMON_PORTS and udp_layer.sport > 1024) or \
                   (udp_layer.dport not in COMMON_PORTS and udp_layer.dport > 1024):
                    self.unusual_ports[(src_ip, udp_layer.sport, udp_layer.dport)] += 1

            elif ICMP in pkt:
                icmp_layer = pkt[ICMP]
                self.icmp_types_count[src_ip][icmp_layer.type] += 1

    def generate_report(self):
        with self.lock:
            syn_packets = dict(self.syn_packets)
            fin_packets = dict(self.fin_packets)
            null_packets = dict(self.null_packets)
            xmas_packets = dict(self.xmas_packets)
            rst_packets = dict(self.rst_packets)
            zero_payload_tcp = self.zero_payload_tcp
            tcp_connection_times = dict(self.tcp_connection_times)
            unusual_ports = dict(self.unusual_ports)
            udp_flood = dict(self.udp_flood)
            udp_ports_per_ip = dict((k, set(v)) for k,v in self.udp_ports_per_ip.items())
            icmp_types_count = dict((k, dict(v)) for k,v in self.icmp_types_count.items())
            total_packets = self.total_packets

        report = {
            "total_packets": total_packets,
            "syn_scaners": [],
            "fin_scaners": [],
            "null_scaners": [],
            "xmas_scaners": [],
            "rst_flooders": [],
            "zero_payload_tcp": zero_payload_tcp,
            "unusual_ports": [],
            "short_tcp_connections": [],
            "udp_flooders": [],
            "udp_port_sweepers": [],
            "icmp_flooders": [],
            "icmp_unusual_types": [],
        }

        SYN_THRESHOLD = 5
        FIN_THRESHOLD = 5
        NULL_THRESHOLD = 5
        XMAS_THRESHOLD = 5
        RST_THRESHOLD = 10
        UDP_FLOOD_THRESHOLD = 100
        UDP_PORT_SWEEP_THRESHOLD = 20
        ICMP_FLOOD_THRESHOLD = 50
        SHORT_CONN_MAX_DURATION = 1.0
        UNUSUAL_PORT_USAGE_THRESHOLD = 2

        for (ip, sport), count in syn_packets.items():
            if count > SYN_THRESHOLD:
                report["syn_scaners"].append({"ip": ip, "src_port": sport, "count": count})

        for (ip, sport), count in fin_packets.items():
            if count > FIN_THRESHOLD:
                report["fin_scaners"].append({"ip": ip, "src_port": sport, "count": count})

        for (ip, sport), count in null_packets.items():
            if count > NULL_THRESHOLD:
                report["null_scaners"].append({"ip": ip, "src_port": sport, "count": count})

        for (ip, sport), count in xmas_packets.items():
            if count > XMAS_THRESHOLD:
                report["xmas_scaners"].append({"ip": ip, "src_port": sport, "count": count})

        for (ip, sport), count in rst_packets.items():
            if count > RST_THRESHOLD:
                report["rst_flooders"].append({"ip": ip, "src_port": sport, "count": count})

        for (ip, sport, dport), count in unusual_ports.items():
            if count > UNUSUAL_PORT_USAGE_THRESHOLD:
                report["unusual_ports"].append({
                    "ip": ip,
                    "src_port": sport,
                    "dst_port": dport,
                    "count": count
                })

        for (src_ip, dst_ip), times in tcp_connection_times.items():
            if len(times) > 1:
                duration = max(times) - min(times)
                if duration < SHORT_CONN_MAX_DURATION:
                    report["short_tcp_connections"].append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "packet_count": len(times),
                        "duration_seconds": round(duration, 3)
                    })

        for (ip, dport), count in udp_flood.items():
            if count > UDP_FLOOD_THRESHOLD:
                report["udp_flooders"].append({"ip": ip, "dst_port": dport, "count": count})

        for ip, ports in udp_ports_per_ip.items():
            if len(ports) > UDP_PORT_SWEEP_THRESHOLD:
                report["udp_port_sweepers"].append({"ip": ip, "distinct_dst_ports": len(ports)})

        for ip, types in icmp_types_count.items():
            total_icmp = sum(types.values())
            if total_icmp > ICMP_FLOOD_THRESHOLD:
                report["icmp_flooders"].append({"ip": ip, "total_icmp": total_icmp})

            for t, c in types.items():
                if t not in (0, 8) and c > 5:
                    report["icmp_unusual_types"].append({"ip": ip, "icmp_type": t, "count": c})

        return report

    def print_report(self, report):
        console.rule("[bold red]Live PCAP Analysis Report[/bold red]", style="red")

        console.print(f"[bold]Total packets analyzed:[/bold] {report['total_packets']}\n")

        def print_table(title, items, columns, no_items_text="No data detected."):
            console.print(f"[bold underline]{title}[/bold underline]")
            if not items:
                console.print(f"[dim]{no_items_text}\n")
                return

            table = Table(box=box.SIMPLE_HEAVY)
            for col in columns:
                table.add_column(col, style="cyan", no_wrap=True)
            for item in items:
                row = [str(item.get(col.lower().replace(" ", "_"), "")) for col in columns]
                table.add_row(*row)
            console.print(table)
            console.print("")

        print_table(
            "Potential SYN scanners",
            report["syn_scaners"],
            ["IP", "Src Port", "Count"]
        )
        print_table(
            "Potential FIN scanners",
            report["fin_scaners"],
            ["IP", "Src Port", "Count"]
        )
        print_table(
            "Potential NULL scanners",
            report["null_scaners"],
            ["IP", "Src Port", "Count"]
        )
        print_table(
            "Potential Xmas scanners",
            report["xmas_scaners"],
            ["IP", "Src Port", "Count"]
        )
        print_table(
            "Potential RST flooders",
            report["rst_flooders"],
            ["IP", "Src Port", "Count"]
        )
        console.print(f"[bold]Zero payload TCP packets:[/bold] {report['zero_payload_tcp']}\n")
        print_table(
            "Unusual ports usage",
            report["unusual_ports"],
            ["IP", "Src Port", "Dst Port", "Count"]
        )
        print_table(
            "Short TCP connections (<1 sec)",
            report["short_tcp_connections"],
            ["Src IP", "Dst IP", "Packet Count", "Duration Seconds"]
        )
        print_table(
            "Potential UDP flooders",
            report["udp_flooders"],
            ["IP", "Dst Port", "Count"]
        )
        print_table(
            "Potential UDP port sweepers",
            report["udp_port_sweepers"],
            ["IP", "Distinct Dst Ports"]
        )
        print_table(
            "Potential ICMP flooders",
            report["icmp_flooders"],
            ["IP", "Total ICMP"]
        )
        print_table(
            "Unusual ICMP types detected",
            report["icmp_unusual_types"],
            ["IP", "ICMP Type", "Count"]
        )

def export_report(report, out_file):
    if out_file.lower().endswith('.json'):
        with open(out_file, 'w') as f:
            json.dump(report, f, indent=4)
        console.print(f"\n[green]Report saved as JSON to {out_file}[/green]")
    else:
        with open(out_file, 'w') as f:
            f.write(f"PCAP Analysis Report\n")
            f.write(f"Total packets: {report['total_packets']}\n\n")

            def write_list(title, items, fields):
                if not items:
                    f.write(f"No {title.lower()} detected.\n\n")
                    return
                f.write(f"{title}:\n")
                for item in items:
                    line = ", ".join(f"{k}={item[k]}" for k in fields)
                    f.write("  " + line + "\n")
                f.write("\n")

            write_list("Potential SYN scanners", report["syn_scaners"], ["ip", "src_port", "count"])
            write_list("Potential FIN scanners", report["fin_scaners"], ["ip", "src_port", "count"])
            write_list("Potential NULL scanners", report["null_scaners"], ["ip", "src_port", "count"])
            write_list("Potential Xmas scanners", report["xmas_scaners"], ["ip", "src_port", "count"])
            write_list("Potential RST flooders", report["rst_flooders"], ["ip", "src_port", "count"])
            f.write(f"Zero payload TCP packets: {report['zero_payload_tcp']}\n\n")
            write_list("Unusual ports usage", report["unusual_ports"], ["ip", "src_port", "dst_port", "count"])
            write_list("Short TCP connections (<1 sec)", report["short_tcp_connections"], ["src_ip", "dst_ip", "packet_count", "duration_seconds"])
            write_list("Potential UDP flooders", report["udp_flooders"], ["ip", "dst_port", "count"])
            write_list("Potential UDP port sweepers", report["udp_port_sweepers"], ["ip", "distinct_dst_ports"])
            write_list("Potential ICMP flooders", report["icmp_flooders"], ["ip", "total_icmp"])
            write_list("Unusual ICMP types detected", report["icmp_unusual_types"], ["ip", "icmp_type", "count"])

        console.print(f"\n[green]Report saved as text to {out_file}[/green]")

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Advanced PCAP Analyzer with live capture support")
    parser.add_argument("-f", "--file", help="Input PCAP file to analyze")
    parser.add_argument("-i", "--interface", help="Network interface for live capture")
    parser.add_argument("-o", "--output", default="report.txt", help="Output report file (txt or json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output to console")
    parser.add_argument("-t", "--interval", type=int, default=10, help="Report interval in seconds for live capture")

    args = parser.parse_args()

    analyzer = Analyzer(verbose=args.verbose, report_interval=args.interval)

    def signal_handler(sig, frame):
        console.print("\n[bold red]Interrupt received, generating final report...[/bold red]")
        report = analyzer.generate_report()
        analyzer.print_report(report)
        export_report(report, args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if args.file:
        console.print(f"[bold]Analyzing PCAP file:[/bold] {args.file}")
        packets = rdpcap(args.file)
        for pkt in packets:
            analyzer.process_packet(pkt)
        report = analyzer.generate_report()
        analyzer.print_report(report)
        export_report(report, args.output)

    elif args.interface:
        console.print(f"[bold]Starting live capture on interface:[/bold] {args.interface}")
        console.print(f"[dim]Press Ctrl+C to stop and save report.[/dim]\n")

        def periodic_report():
            while analyzer.running:
                time.sleep(analyzer.report_interval)
                report = analyzer.generate_report()
                if args.verbose:
                    console.print("\n[bold blue][Periodic Report][/bold blue]")
                    analyzer.print_report(report)

        report_thread = threading.Thread(target=periodic_report, daemon=True)
        report_thread.start()

        sniff(iface=args.interface, prn=analyzer.process_packet, store=False)

    else:
        console.print("[bold red]You must specify either a PCAP file (-f) or network interface (-i) to capture live.[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
