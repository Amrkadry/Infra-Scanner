#!/usr/bin/env python3

import subprocess
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configuration
MAX_THREADS = 10
TIMEOUT_PING = 60
TIMEOUT_FAST = 300
TIMEOUT_FULL = 1800
TIMEOUT_UDP = 900

def print_status(message, status_type="info"):
    """Print colored status messages"""
    colors = {
        "info": "\033[94m[~]\033[0m",
        "success": "\033[92m[+]\033[0m", 
        "error": "\033[91m[-]\033[0m",
        "warning": "\033[93m[!]\033[0m"
    }
    print(f"{colors.get(status_type, '[*]')} {message}")

class NetworkScanner:
    def __init__(self, input_file, skip_ping=False):
        self.input_file = input_file
        self.output_folder = "nmap_results"
        self.skip_ping = skip_ping
        self.live_hosts_file = os.path.join(self.output_folder, "live_hosts.txt")
        self.summary_file = os.path.join(self.output_folder, "scan_summary.txt")
        self.udp_summary_file = os.path.join(self.output_folder, "udp_summary.txt")
        self.lock = threading.Lock()
        
    def expand_targets(self, targets):
        """Expand CIDR ranges and individual IPs to list of IPs"""
        all_ips = []
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
                
            if '/' in target:  # CIDR notation
                try:
                    import ipaddress
                    network = ipaddress.IPv4Network(target, strict=False)
                    all_ips.extend([str(ip) for ip in network.hosts()])
                except:
                    # If ipaddress fails, treat as regular target
                    all_ips.append(target)
            elif '-' in target and target.count('.') == 3:  # Range like 192.168.1.1-10
                try:
                    base = '.'.join(target.split('.')[:-1])
                    last_octet = target.split('.')[-1]
                    if '-' in last_octet:
                        start, end = last_octet.split('-')
                        for i in range(int(start), int(end) + 1):
                            all_ips.append(f"{base}.{i}")
                    else:
                        all_ips.append(target)
                except:
                    all_ips.append(target)
            else:
                all_ips.append(target)
        
        return all_ips
        
    def discover_live_hosts(self, target):
        """Discover live hosts using -Pn with port scanning"""
        print_status(f"Discovering live hosts on {target} using -Pn...")
        live_hosts = []
        
        try:
            # Use -Pn with top common ports to detect live hosts
            # This skips ping and directly tries to connect to ports
            result = subprocess.run(
                ["nmap", "-Pn", "-sS", "--top-ports", "100", "-T4", "--max-retries", "1", "--host-timeout", "60s", target],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_PING
            )
            
            for line in result.stdout.splitlines():
                if line.startswith("Nmap scan report for"):
                    # Extract IP address - handle different formats:
                    # "Nmap scan report for 192.168.1.1"
                    # "Nmap scan report for hostname (192.168.1.1)"
                    if "(" in line and ")" in line:
                        # Format: "Nmap scan report for hostname (192.168.1.1)"
                        ip = line.split("(")[1].split(")")[0]
                    else:
                        # Format: "Nmap scan report for 192.168.1.1"
                        ip = line.split()[-1]
                    
                    # Validate IP format
                    if self.is_valid_ip(ip):
                        live_hosts.append(ip)
            
            print_status(f"Found {len(live_hosts)} live hosts in {target}", "success")
            return live_hosts
            
        except subprocess.TimeoutExpired:
            print_status(f"Host discovery timeout on {target}", "error")
            return live_hosts  # Return any hosts found before timeout
        except Exception as e:
            print_status(f"Error in host discovery for {target}: {e}", "error")
            return live_hosts  # Return any hosts found before error
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except ValueError:
            return False
    
    def fast_scan_1000(self, ip):
        """Fast scan on top 1000 ports"""
        print_status(f"Fast scan (top 1000 ports) on {ip}...")
        out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-1000.txt")
        
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-sCV", "-T4", "--top-ports", "1000", ip],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_FAST
            )
            
            with open(out_file, "w") as f:
                f.write(result.stdout)
            
            # Extract open ports
            open_ports = []
            for line in result.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split("/")[0].strip()
                    service_info = " ".join(line.split()[2:])
                    open_ports.append(f"{port}:{service_info}")
            
            print_status(f"Fast scan completed for {ip} - {len(open_ports)} open ports", "success")
            return ip, open_ports, True
            
        except subprocess.TimeoutExpired:
            print_status(f"Fast scan timeout on {ip}", "error")
            with open(out_file, "w") as f:
                f.write("Fast scan timed out.\n")
            return ip, [], False
        except Exception as e:
            print_status(f"Error in fast scan for {ip}: {e}", "error")
            return ip, [], False
    
    def full_port_scan(self, ip):
        """Full port scan on all 65535 ports"""
        print_status(f"Full port scan (all ports) on {ip}...")
        out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-full.txt")
        
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-sCV", "-T4", "-p-", ip],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_FULL
            )
            
            with open(out_file, "w") as f:
                f.write(result.stdout)
            
            # Extract open ports
            open_ports = []
            for line in result.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split("/")[0].strip()
                    service_info = " ".join(line.split()[2:])
                    open_ports.append(f"{port}:{service_info}")
            
            print_status(f"Full scan completed for {ip} - {len(open_ports)} open ports", "success")
            return ip, open_ports, True
            
        except subprocess.TimeoutExpired:
            print_status(f"Full scan timeout on {ip}", "error")
            with open(out_file, "w") as f:
                f.write("Full port scan timed out.\n")
            return ip, [], False
        except Exception as e:
            print_status(f"Error in full scan for {ip}: {e}", "error")
            return ip, [], False
    
    def udp_scan(self, ip):
        """UDP scan on common ports"""
        print_status(f"UDP scan on {ip}...")
        out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-udp.txt")
        
        try:
            # Common UDP ports
            udp_ports = "53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353"
            
            result = subprocess.run(
                ["nmap", "-Pn", "-sU", "-T4", f"-p{udp_ports}", ip],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_UDP
            )
            
            with open(out_file, "w") as f:
                f.write(result.stdout)
            
            # Extract open UDP ports
            open_ports = []
            for line in result.stdout.splitlines():
                if "/udp" in line and ("open" in line or "open|filtered" in line):
                    port = line.split("/")[0].strip()
                    service_info = " ".join(line.split()[2:])
                    open_ports.append(f"{port}:{service_info}")
            
            print_status(f"UDP scan completed for {ip} - {len(open_ports)} open/filtered ports", "success")
            return ip, open_ports, True
            
        except subprocess.TimeoutExpired:
            print_status(f"UDP scan timeout on {ip}", "error")
            with open(out_file, "w") as f:
                f.write("UDP scan timed out.\n")
            return ip, [], False
        except Exception as e:
            print_status(f"Error in UDP scan for {ip}: {e}", "error")
            return ip, [], False
    
    def snmp_check(self, ip, community="public"):
        """Check for SNMP misconfigurations"""
        print_status(f"SNMP check on {ip}...")
        out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-snmp.txt")
        
        try:
            # First check if SNMP port is open
            port_check = subprocess.run(
                ["nmap", "-sU", "-p", "161", "-Pn", "--open", ip],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if "161/udp open" not in port_check.stdout:
                print_status(f"SNMP port not open on {ip}", "warning")
                return ip, False, "Port 161/udp not open"
            
            # Run snmpwalk
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, ip, "1.3.6.1.2.1.1"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            with open(out_file, "w") as f:
                f.write(f"SNMP check for {ip} with community '{community}'\n")
                f.write("=" * 50 + "\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\nErrors:\n")
                    f.write(result.stderr)
            
            if result.returncode == 0 and result.stdout.strip():
                print_status(f"SNMP accessible on {ip} with community '{community}'", "success")
                return ip, True, "SNMP accessible"
            else:
                print_status(f"SNMP not accessible on {ip} with community '{community}'", "warning")
                return ip, False, "SNMP not accessible with given community"
                
        except subprocess.TimeoutExpired:
            print_status(f"SNMP check timeout on {ip}", "error")
            return ip, False, "Timeout"
        except FileNotFoundError:
            print_status(f"snmpwalk not found. Install snmp-utils package", "error")
            return ip, False, "snmpwalk not installed"
        except Exception as e:
            print_status(f"Error in SNMP check for {ip}: {e}", "error")
            return ip, False, str(e)
    
    def run_comprehensive_scan(self):
        """Run the complete scanning workflow"""
        print_status("Starting comprehensive network scan...", "info")
        
        try:
            with open(self.input_file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print_status(f"Input file not found: {self.input_file}", "error")
            return
        
        all_live_hosts = []
        
        if self.skip_ping:
            # Skip host discovery, expand targets directly
            print_status("=== SKIPPING HOST DISCOVERY (ASSUMING ALL TARGETS ARE LIVE) ===", "warning")
            all_live_hosts = self.expand_targets(targets)
            print_status(f"Treating {len(all_live_hosts)} targets as live hosts", "info")
        else:
            # Stage 1: Host discovery using -Pn
            print_status("=== STAGE 1: HOST DISCOVERY (using -Pn) ===", "info")
            
            for target in targets:
                live_hosts = self.discover_live_hosts(target)
                all_live_hosts.extend(live_hosts)
        
        # Remove duplicates
        all_live_hosts = list(set(all_live_hosts))
        
        # Save live hosts
        with open(self.live_hosts_file, "w") as f:
            for ip in all_live_hosts:
                f.write(ip + "\n")
        
        print_status(f"Total live hosts: {len(all_live_hosts)}", "success")
        
        if not all_live_hosts:
            print_status("No live hosts found. Try using --skip-ping if you know hosts are live.", "error")
            return
        
        # Stage 2: Fast scan (top 1000 ports)
        fast_results = []
        if not self.skip_fast:
            print_status("=== STAGE 2: FAST SCAN (TOP 1000 PORTS) ===", "info")
            
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                future_to_ip = {executor.submit(self.fast_scan_1000, ip): ip for ip in all_live_hosts}
                for future in as_completed(future_to_ip):
                    ip, ports, success = future.result()
                    fast_results.append((ip, ports, success))
        else:
            print_status("=== SKIPPING STAGE 2: FAST SCAN ===", "warning")

        # Stage 3: Full port scan
        full_results = []
        if not self.skip_full:
            print_status("=== STAGE 3: FULL PORT SCAN (ALL PORTS) ===", "info")
            
            with ThreadPoolExecutor(max_workers=min(5, MAX_THREADS)) as executor:
                future_to_ip = {executor.submit(self.full_port_scan, ip): ip for ip in all_live_hosts}
                for future in as_completed(future_to_ip):
                    ip, ports, success = future.result()
                    full_results.append((ip, ports, success))
        else:
            print_status("=== SKIPPING STAGE 3: FULL PORT SCAN ===", "warning")

        # Stage 4: UDP scan
        udp_results = []
        if not self.skip_udp:
            print_status("=== STAGE 4: UDP SCAN ===", "info")
            
            with ThreadPoolExecutor(max_workers=min(3, MAX_THREADS)) as executor:
                future_to_ip = {executor.submit(self.udp_scan, ip): ip for ip in all_live_hosts}
                for future in as_completed(future_to_ip):
                    ip, ports, success = future.result()
                    udp_results.append((ip, ports, success))
        else:
            print_status("=== SKIPPING STAGE 4: UDP SCAN ===", "warning")

        # Stage 5: SNMP check
        snmp_results = []
        if not self.skip_snmp:
            print_status("=== STAGE 5: SNMP CONFIGURATION CHECK ===", "info")
            
            # Check only hosts that have UDP port 161 open/filtered
            snmp_candidates = []
            if udp_results:  # Only if UDP scan was performed
                for ip, ports, success in udp_results:
                    if any("161:" in port for port in ports):
                        snmp_candidates.append(ip)
            else:
                # If UDP scan was skipped, check all live hosts
                snmp_candidates = all_live_hosts
            
            if snmp_candidates:
                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    future_to_ip = {executor.submit(self.snmp_check, ip): ip for ip in snmp_candidates}
                    for future in as_completed(future_to_ip):
                        ip, accessible, message = future.result()
                        snmp_results.append((ip, accessible, message))
        else:
            print_status("=== SKIPPING STAGE 5: SNMP CHECK ===", "warning")
        
        # Generate summary reports
        self.generate_summary_reports(fast_results, full_results, udp_results, snmp_results)
        
        print_status("Comprehensive scan completed!", "success")
        print_status(f"Results saved in '{self.output_folder}' directory", "info")
    
    def generate_summary_reports(self, fast_results, full_results, udp_results, snmp_results):
        """Generate summary reports"""
        
        # TCP Summary
        with open(self.summary_file, "w") as f:
            f.write("NETWORK SCAN SUMMARY REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            if fast_results:
                f.write("FAST SCAN RESULTS (TOP 1000 PORTS):\n")
                f.write("-" * 40 + "\n")
                for ip, ports, success in fast_results:
                    status = "SUCCESS" if success else "FAILED/TIMEOUT"
                    f.write(f"{ip} [{status}]: {', '.join(ports) if ports else 'No open ports'}\n")
                f.write("\n")
            else:
                f.write("FAST SCAN: SKIPPED\n\n")
            
            if full_results:
                f.write("FULL SCAN RESULTS (ALL PORTS):\n")
                f.write("-" * 40 + "\n")
                for ip, ports, success in full_results:
                    status = "SUCCESS" if success else "FAILED/TIMEOUT"
                    f.write(f"{ip} [{status}]: {', '.join(ports) if ports else 'No open ports'}\n")
            else:
                f.write("FULL SCAN: SKIPPED\n")
        
        # UDP Summary
        if udp_results:
            with open(self.udp_summary_file, "w") as f:
                f.write("UDP SCAN SUMMARY REPORT\n")
                f.write("=" * 30 + "\n\n")
                for ip, ports, success in udp_results:
                    status = "SUCCESS" if success else "FAILED/TIMEOUT"
                    f.write(f"{ip} [{status}]: {', '.join(ports) if ports else 'No open UDP ports'}\n")
        
        # SNMP Summary
        if snmp_results:
            snmp_summary_file = os.path.join(self.output_folder, "snmp_summary.txt")
            with open(snmp_summary_file, "w") as f:
                f.write("SNMP CONFIGURATION CHECK SUMMARY\n")
                f.write("=" * 40 + "\n\n")
                for ip, accessible, message in snmp_results:
                    status = "VULNERABLE" if accessible else "SECURE/INACCESSIBLE"
                    f.write(f"{ip} [{status}]: {message}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced Multi-Stage Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enhanced_nmap.py targets.txt                    # Run all stages
  python3 enhanced_nmap.py targets.txt --skip-ping       # Skip host discovery
  python3 enhanced_nmap.py targets.txt --skip-full       # Skip full port scan
  python3 enhanced_nmap.py targets.txt --skip-udp --skip-snmp  # TCP only
  python3 enhanced_nmap.py targets.txt --fast-only       # Only fast scan
  python3 enhanced_nmap.py targets.txt --udp-only        # Only UDP scan
        """
    )
    
    parser.add_argument('targets_file', help='File containing target IPs/ranges')
    
    # Skip options
    parser.add_argument('--skip-ping', action='store_true', 
                       help='Skip host discovery (assume all targets are live)')
    parser.add_argument('--skip-fast', action='store_true',
                       help='Skip fast scan (top 1000 ports)')
    parser.add_argument('--skip-full', action='store_true',
                       help='Skip full port scan (all 65535 ports)')
    parser.add_argument('--skip-udp', action='store_true',
                       help='Skip UDP scan')
    parser.add_argument('--skip-snmp', action='store_true',
                       help='Skip SNMP configuration check')
    
    # Convenience options (combinations)
    parser.add_argument('--fast-only', action='store_true',
                       help='Only run host discovery and fast scan')
    parser.add_argument('--tcp-only', action='store_true',
                       help='Only run TCP scans (skip UDP and SNMP)')
    parser.add_argument('--udp-only', action='store_true',
                       help='Only run host discovery and UDP/SNMP scans')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.targets_file):
        print_status(f"Input file not found: {args.targets_file}", "error")
        sys.exit(1)
    
    # Process convenience options
    skip_ping = args.skip_ping
    skip_fast = args.skip_fast
    skip_full = args.skip_full
    skip_udp = args.skip_udp
    skip_snmp = args.skip_snmp
    
    if args.fast_only:
        skip_full = True
        skip_udp = True
        skip_snmp = True
        print_status("Fast-only mode: Skipping full scan, UDP scan, and SNMP check", "info")
    
    if args.tcp_only:
        skip_udp = True
        skip_snmp = True
        print_status("TCP-only mode: Skipping UDP scan and SNMP check", "info")
    
    if args.udp_only:
        skip_fast = True
        skip_full = True
        print_status("UDP-only mode: Skipping TCP scans", "info")
    
    # Validate that at least one scan type is enabled
    if skip_fast and skip_full and skip_udp:
        print_status("Error: Cannot skip all scan types!", "error")
        sys.exit(1)
    
    print_status("Scan Configuration:", "info")
    print_status(f"  Host Discovery: {'SKIP' if skip_ping else 'RUN'}", "info")
    print_status(f"  Fast Scan: {'SKIP' if skip_fast else 'RUN'}", "info")
    print_status(f"  Full Scan: {'SKIP' if skip_full else 'RUN'}", "info")
    print_status(f"  UDP Scan: {'SKIP' if skip_udp else 'RUN'}", "info")
    print_status(f"  SNMP Check: {'SKIP' if skip_snmp else 'RUN'}", "info")
    print("")
    
    scanner = NetworkScanner(
        args.targets_file, 
        skip_ping=skip_ping,
        skip_fast=skip_fast,
        skip_full=skip_full,
        skip_udp=skip_udp,
        skip_snmp=skip_snmp
    )
    scanner.run_comprehensive_scan()

if __name__ == "__main__":
    main()
