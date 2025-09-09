#!/usr/bin/env python3

import subprocess
import os
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import argparse
import json

# Configuration
MAX_THREADS = 10
TIMEOUT_PING = 60
TIMEOUT_FAST = 300
TIMEOUT_FULL = 1800
TIMEOUT_UDP = 900

class Colors:
    """ANSI color codes for enhanced terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'

def print_banner():
    """Print colorful banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║                      ENHANCED NETWORK SCANNER                       ║
║                         Multi-Stage Analysis                        ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)

def print_status(message, status_type="info", indent=0):
    """Print enhanced colored status messages with better formatting"""
    indent_str = "  " * indent
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    status_configs = {
        "info": {
            "symbol": "ℹ",
            "color": Colors.BLUE,
            "bg": ""
        },
        "success": {
            "symbol": "✓",
            "color": Colors.GREEN,
            "bg": ""
        },
        "error": {
            "symbol": "✗",
            "color": Colors.RED,
            "bg": ""
        },
        "warning": {
            "symbol": "⚠",
            "color": Colors.YELLOW,
            "bg": ""
        },
        "progress": {
            "symbol": "⚡",
            "color": Colors.CYAN,
            "bg": ""
        },
        "discovery": {
            "symbol": "🔍",
            "color": Colors.MAGENTA,
            "bg": ""
        },
        "scan": {
            "symbol": "🚀",
            "color": Colors.CYAN,
            "bg": ""
        },
        "complete": {
            "symbol": "🎯",
            "color": Colors.GREEN,
            "bg": Colors.BG_GREEN
        }
    }
    
    config = status_configs.get(status_type, status_configs["info"])
    
    formatted_message = (
        f"{indent_str}{config['color']}{config['bg']}"
        f"[{config['symbol']}] {Colors.WHITE}{timestamp}{Colors.END} "
        f"{config['color']}{message}{Colors.END}"
    )
    
    print(formatted_message)

def print_section_header(title, stage_num=None):
    """Print colorful section headers"""
    if stage_num:
        header = f"""
{Colors.HEADER}{Colors.BOLD}
{'='*80}
    STAGE {stage_num}: {title}
{'='*80}
{Colors.END}"""
    else:
        header = f"""
{Colors.CYAN}{Colors.BOLD}
{'='*60}
    {title}
{'='*60}
{Colors.END}"""
    print(header)

def print_progress_bar(current, total, prefix="Progress", length=50):
    """Print colorful progress bar"""
    percent = 100 * (current / float(total))
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    
    color = Colors.GREEN if percent == 100 else Colors.YELLOW if percent > 50 else Colors.RED
    
    print(f'\r{Colors.CYAN}{prefix}{Colors.END}: |{color}{bar}{Colors.END}| '
          f'{Colors.WHITE}{percent:.1f}%{Colors.END} ({current}/{total})', end='', flush=True)
    
    if current == total:
        print()  # New line when complete

class NetworkScanner:
    def __init__(self, input_file, skip_ping=False, skip_fast=False, skip_full=False, skip_udp=False, skip_snmp=False):
        self.input_file = input_file
        self.output_folder = "nmap_results"
        self.skip_ping = skip_ping
        self.skip_fast = skip_fast
        self.skip_full = skip_full
        self.skip_udp = skip_udp
        self.skip_snmp = skip_snmp
        
        # Enhanced output files
        self.live_hosts_file = os.path.join(self.output_folder, "live_hosts.txt")
        self.consolidated_report = os.path.join(self.output_folder, "CONSOLIDATED_SCAN_REPORT.txt")
        self.json_report = os.path.join(self.output_folder, "scan_results.json")
        self.detailed_log = os.path.join(self.output_folder, "detailed_scan.log")
        
        self.lock = threading.Lock()
        self.scan_results = {
            'scan_info': {
                'start_time': datetime.now().isoformat(),
                'target_file': input_file,
                'stages': {
                    'host_discovery': not skip_ping,
                    'fast_scan': not skip_fast,
                    'full_scan': not skip_full,
                    'udp_scan': not skip_udp,
                    'snmp_scan': not skip_snmp
                }
            },
            'live_hosts': [],
            'fast_scan_results': [],
            'full_scan_results': [],
            'udp_scan_results': [],
            'snmp_scan_results': []
        }
        
        # Create output directory
        os.makedirs(self.output_folder, exist_ok=True)
        
        # Initialize log file
        with open(self.detailed_log, 'w') as f:
            f.write(f"Enhanced Network Scanner - Detailed Log\n")
            f.write(f"Started: {datetime.now()}\n")
            f.write(f"{'='*80}\n\n")

    def log_to_file(self, message, log_type="INFO"):
        """Log messages to detailed log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.detailed_log, 'a') as f:
            f.write(f"[{timestamp}] [{log_type}] {message}\n")

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

    def expand_targets(self, targets):
        """Expand CIDR ranges and individual IPs to list of IPs"""
        all_ips = []
        
        print_status("Expanding target ranges...", "progress")
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
                
            if '/' in target:  # CIDR notation
                try:
                    import ipaddress
                    network = ipaddress.IPv4Network(target, strict=False)
                    ips = [str(ip) for ip in network.hosts()]
                    all_ips.extend(ips)
                    print_status(f"Expanded {target} to {len(ips)} hosts", "info", 1)
                except Exception as e:
                    all_ips.append(target)
                    print_status(f"Could not expand {target}: {e}", "warning", 1)
            elif '-' in target and target.count('.') == 3:  # Range like 192.168.1.1-10
                try:
                    base = '.'.join(target.split('.')[:-1])
                    last_octet = target.split('.')[-1]
                    if '-' in last_octet:
                        start, end = last_octet.split('-')
                        range_ips = []
                        for i in range(int(start), int(end) + 1):
                            range_ips.append(f"{base}.{i}")
                        all_ips.extend(range_ips)
                        print_status(f"Expanded range {target} to {len(range_ips)} hosts", "info", 1)
                    else:
                        all_ips.append(target)
                except Exception as e:
                    all_ips.append(target)
                    print_status(f"Could not expand range {target}: {e}", "warning", 1)
            else:
                all_ips.append(target)
        
        return all_ips
    
    def discover_live_hosts(self, target):
        """Discover live hosts using -Pn with port scanning"""
        print_status(f"Discovering live hosts in {Colors.YELLOW}{target}{Colors.END}...", "discovery")
        self.log_to_file(f"Starting host discovery for {target}")
        
        live_hosts = []
        
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-sS", "--top-ports", "100", "-T4", "--max-retries", "1", "--host-timeout", "60s", target],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_PING
            )
            
            for line in result.stdout.splitlines():
                if line.startswith("Nmap scan report for"):
                    if "(" in line and ")" in line:
                        ip = line.split("(")[1].split(")")[0]
                    else:
                        ip = line.split()[-1]
                    
                    if self.is_valid_ip(ip):
                        live_hosts.append(ip)
                        print_status(f"Found live host: {Colors.GREEN}{ip}{Colors.END}", "success", 1)
            
            self.log_to_file(f"Host discovery for {target} completed. Found {len(live_hosts)} live hosts")
            print_status(f"Discovery complete for {target}: {Colors.GREEN}{len(live_hosts)}{Colors.END} live hosts", "complete")
            return live_hosts
            
        except subprocess.TimeoutExpired:
            error_msg = f"Host discovery timeout for {target}"
            print_status(error_msg, "error")
            self.log_to_file(error_msg, "ERROR")
            return live_hosts
        except Exception as e:
            error_msg = f"Error in host discovery for {target}: {e}"
            print_status(error_msg, "error")
            self.log_to_file(error_msg, "ERROR")
            return live_hosts
    
    def fast_scan_1000(self, ip):
        """Fast scan on top 1000 ports with enhanced output"""
        print_status(f"Fast scanning {Colors.CYAN}{ip}{Colors.END} (top 1000 ports)...", "scan")
        self.log_to_file(f"Starting fast scan for {ip}")
        
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-sCV", "-T4", "--top-ports", "1000", ip],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_FAST
            )
            
            # Parse results
            open_ports = []
            service_details = {}
            
            for line in result.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0].split("/")[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        
                        open_ports.append(port)
                        service_details[port] = {
                            'service': service,
                            'version': version,
                            'full_line': line.strip()
                        }
            
            # Save individual result
            out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-fast.txt")
            with open(out_file, "w") as f:
                f.write(f"FAST SCAN RESULTS FOR {ip}\n")
                f.write(f"Scan completed: {datetime.now()}\n")
                f.write("="*60 + "\n\n")
                f.write(result.stdout)
            
            status_msg = f"Fast scan complete for {Colors.GREEN}{ip}{Colors.END}: {Colors.YELLOW}{len(open_ports)}{Colors.END} open ports"
            if open_ports:
                status_msg += f" ({', '.join(open_ports[:5])}{'...' if len(open_ports) > 5 else ''})"
            
            print_status(status_msg, "complete", 1)
            self.log_to_file(f"Fast scan completed for {ip}. Found {len(open_ports)} open ports: {', '.join(open_ports)}")
            
            return {
                'ip': ip,
                'open_ports': open_ports,
                'service_details': service_details,
                'success': True,
                'scan_output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            error_msg = f"Fast scan timeout for {ip}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'open_ports': [], 'service_details': {}, 'success': False, 'error': 'timeout'}
        except Exception as e:
            error_msg = f"Fast scan error for {ip}: {e}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'open_ports': [], 'service_details': {}, 'success': False, 'error': str(e)}
    
    def full_port_scan(self, ip):
        """Full port scan on all 65535 ports"""
        print_status(f"Full scanning {Colors.MAGENTA}{ip}{Colors.END} (all 65535 ports)...", "scan")
        self.log_to_file(f"Starting full port scan for {ip}")
        
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-sCV", "-T4", "-p-", ip],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_FULL
            )
            
            # Parse results
            open_ports = []
            service_details = {}
            
            for line in result.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0].split("/")[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        
                        open_ports.append(port)
                        service_details[port] = {
                            'service': service,
                            'version': version,
                            'full_line': line.strip()
                        }
            
            # Save individual result
            out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-full.txt")
            with open(out_file, "w") as f:
                f.write(f"FULL PORT SCAN RESULTS FOR {ip}\n")
                f.write(f"Scan completed: {datetime.now()}\n")
                f.write("="*60 + "\n\n")
                f.write(result.stdout)
            
            print_status(f"Full scan complete for {Colors.GREEN}{ip}{Colors.END}: {Colors.YELLOW}{len(open_ports)}{Colors.END} open ports", "complete", 1)
            self.log_to_file(f"Full port scan completed for {ip}. Found {len(open_ports)} open ports: {', '.join(open_ports)}")
            
            return {
                'ip': ip,
                'open_ports': open_ports,
                'service_details': service_details,
                'success': True,
                'scan_output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            error_msg = f"Full scan timeout for {ip}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'open_ports': [], 'service_details': {}, 'success': False, 'error': 'timeout'}
        except Exception as e:
            error_msg = f"Full scan error for {ip}: {e}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'open_ports': [], 'service_details': {}, 'success': False, 'error': str(e)}
    
    def udp_scan(self, ip):
        """UDP scan on common ports"""
        print_status(f"UDP scanning {Colors.BLUE}{ip}{Colors.END}...", "scan")
        self.log_to_file(f"Starting UDP scan for {ip}")
        
        try:
            udp_ports = "53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353"
            
            result = subprocess.run(
                ["nmap", "-Pn", "-sU", "-T4", f"-p{udp_ports}", ip],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_UDP
            )
            
            # Parse results
            open_ports = []
            service_details = {}
            
            for line in result.stdout.splitlines():
                if "/udp" in line and ("open" in line or "open|filtered" in line):
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0].split("/")[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        state = parts[1] if len(parts) > 1 else "unknown"
                        
                        open_ports.append(port)
                        service_details[port] = {
                            'service': service,
                            'state': state,
                            'full_line': line.strip()
                        }
            
            # Save individual result
            out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-udp.txt")
            with open(out_file, "w") as f:
                f.write(f"UDP SCAN RESULTS FOR {ip}\n")
                f.write(f"Scan completed: {datetime.now()}\n")
                f.write("="*60 + "\n\n")
                f.write(result.stdout)
            
            print_status(f"UDP scan complete for {Colors.GREEN}{ip}{Colors.END}: {Colors.YELLOW}{len(open_ports)}{Colors.END} open/filtered ports", "complete", 1)
            self.log_to_file(f"UDP scan completed for {ip}. Found {len(open_ports)} open/filtered ports: {', '.join(open_ports)}")
            
            return {
                'ip': ip,
                'open_ports': open_ports,
                'service_details': service_details,
                'success': True,
                'scan_output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            error_msg = f"UDP scan timeout for {ip}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'open_ports': [], 'service_details': {}, 'success': False, 'error': 'timeout'}
        except Exception as e:
            error_msg = f"UDP scan error for {ip}: {e}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'open_ports': [], 'service_details': {}, 'success': False, 'error': str(e)}
    
    def snmp_check(self, ip, community="public"):
        """Check for SNMP misconfigurations"""
        print_status(f"SNMP checking {Colors.YELLOW}{ip}{Colors.END}...", "scan")
        self.log_to_file(f"Starting SNMP check for {ip}")
        
        try:
            # First check if SNMP port is open
            port_check = subprocess.run(
                ["nmap", "-sU", "-p", "161", "-Pn", "--open", ip],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if "161/udp open" not in port_check.stdout:
                msg = f"SNMP port not open on {ip}"
                print_status(msg, "warning", 1)
                self.log_to_file(msg, "WARNING")
                return {'ip': ip, 'accessible': False, 'message': 'Port 161/udp not open', 'success': True}
            
            # Run snmpwalk
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, ip, "1.3.6.1.2.1.1"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Save individual result
            out_file = os.path.join(self.output_folder, f"{ip.replace('.', '_')}-snmp.txt")
            with open(out_file, "w") as f:
                f.write(f"SNMP CHECK RESULTS FOR {ip}\n")
                f.write(f"Community: {community}\n")
                f.write(f"Scan completed: {datetime.now()}\n")
                f.write("="*60 + "\n\n")
                f.write("Port Check Output:\n")
                f.write(port_check.stdout)
                f.write("\n" + "="*40 + "\n")
                f.write("SNMP Walk Output:\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\nErrors:\n")
                    f.write(result.stderr)
            
            if result.returncode == 0 and result.stdout.strip():
                print_status(f"SNMP accessible on {Colors.RED}{ip}{Colors.END} with community '{community}'", "error", 1)
                self.log_to_file(f"SNMP vulnerable: {ip} accessible with community '{community}'", "WARNING")
                return {'ip': ip, 'accessible': True, 'message': f'SNMP accessible with community "{community}"', 'success': True, 'snmp_data': result.stdout}
            else:
                print_status(f"SNMP secured on {Colors.GREEN}{ip}{Colors.END}", "success", 1)
                self.log_to_file(f"SNMP secure: {ip} not accessible with community '{community}'")
                return {'ip': ip, 'accessible': False, 'message': f'SNMP not accessible with community "{community}"', 'success': True}
                
        except subprocess.TimeoutExpired:
            error_msg = f"SNMP check timeout for {ip}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'accessible': False, 'message': 'Timeout', 'success': False}
        except FileNotFoundError:
            error_msg = "snmpwalk not found. Install snmp-utils package"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'accessible': False, 'message': 'snmpwalk not installed', 'success': False}
        except Exception as e:
            error_msg = f"SNMP check error for {ip}: {e}"
            print_status(error_msg, "error", 1)
            self.log_to_file(error_msg, "ERROR")
            return {'ip': ip, 'accessible': False, 'message': str(e), 'success': False}
    
    def generate_consolidated_report(self):
        """Generate a comprehensive consolidated report"""
        print_status("Generating consolidated report...", "progress")
        
        report_content = []
        
        # Header
        report_content.append("═" * 100)
        report_content.append("                           CONSOLIDATED NETWORK SCAN REPORT")
        report_content.append("═" * 100)
        report_content.append(f"Scan Started: {self.scan_results['scan_info']['start_time']}")
        report_content.append(f"Scan Completed: {datetime.now().isoformat()}")
        report_content.append(f"Target File: {self.scan_results['scan_info']['target_file']}")
        report_content.append(f"Total Live Hosts: {len(self.scan_results['live_hosts'])}")
        report_content.append("")
        
        # Scan Configuration
        report_content.append("SCAN CONFIGURATION:")
        report_content.append("-" * 50)
        stages = self.scan_results['scan_info']['stages']
        for stage, enabled in stages.items():
            status = "✓ ENABLED" if enabled else "✗ SKIPPED"
            report_content.append(f"  {stage.replace('_', ' ').title():.<30} {status}")
        report_content.append("")
        
        # Live Hosts Summary
        if self.scan_results['live_hosts']:
            report_content.append("LIVE HOSTS:")
            report_content.append("-" * 50)
            for i, host in enumerate(self.scan_results['live_hosts'], 1):
                report_content.append(f"  {i:3d}. {host}")
            report_content.append("")
        
        # Fast Scan Results
        if self.scan_results['fast_scan_results']:
            report_content.append("FAST SCAN RESULTS (TOP 1000 PORTS):")
            report_content.append("═" * 80)
            for result in self.scan_results['fast_scan_results']:
                ip = result['ip']
                if result['success']:
                    report_content.append(f"\n🖥️  {ip}")
                    report_content.append("   " + "─" * 50)
                    if result['open_ports']:
                        for port in result['open_ports']:
                            service_info = result['service_details'].get(port, {})
                            service_name = service_info.get('service', 'unknown')
                            version = service_info.get('version', '')
                            report_content.append(f"   ➤ Port {port:>5}/tcp │ {service_name:<15} │ {version}")
                    else:
                        report_content.append("   ➤ No open ports found")
                else:
                    error = result.get('error', 'unknown error')
                    report_content.append(f"\n❌ {ip} - FAILED ({error})")
            report_content.append("")
        
        # Full Scan Results
        if self.scan_results['full_scan_results']:
            report_content.append("FULL PORT SCAN RESULTS (ALL 65535 PORTS):")
            report_content.append("═" * 80)
            for result in self.scan_results['full_scan_results']:
                ip = result['ip']
                if result['success']:
                    report_content.append(f"\n🔍 {ip}")
                    report_content.append("   " + "─" * 50)
                    if result['open_ports']:
                        for port in result['open_ports']:
                            service_info = result['service_details'].get(port, {})
                            service_name = service_info.get('service', 'unknown')
                            version = service_info.get('version', '')
                            report_content.append(f"   ➤ Port {port:>5}/tcp │ {service_name:<15} │ {version}")
                    else:
                        report_content.append("   ➤ No open ports found")
                else:
                    error = result.get('error', 'unknown error')
                    report_content.append(f"\n❌ {ip} - FAILED ({error})")
            report_content.append("")
        
        # UDP Scan Results
        if self.scan_results['udp_scan_results']:
            report_content.append("UDP SCAN RESULTS:")
            report_content.append("═" * 80)
            for result in self.scan_results['udp_scan_results']:
                ip = result['ip']
                if result['success']:
                    report_content.append(f"\n📡 {ip}")
                    report_content.append("   " + "─" * 50)
                    if result['open_ports']:
                        for port in result['open_ports']:
                            service_info = result['service_details'].get(port, {})
                            service_name = service_info.get('service', 'unknown')
                            state = service_info.get('state', 'unknown')
                            report_content.append(f"   ➤ Port {port:>5}/udp │ {service_name:<15} │ {state}")
                    else:
                        report_content.append("   ➤ No open/filtered UDP ports found")
                else:
                    error = result.get('error', 'unknown error')
                    report_content.append(f"\n❌ {ip} - FAILED ({error})")
            report_content.append("")
        
        # SNMP Scan Results
        if self.scan_results['snmp_scan_results']:
            report_content.append("SNMP CONFIGURATION CHECK:")
            report_content.append("═" * 80)
            vulnerable_hosts = []
            secure_hosts = []
            
            for result in self.scan_results['snmp_scan_results']:
                ip = result['ip']
                if result['success']:
                    if result['accessible']:
                        vulnerable_hosts.append(f"   ⚠️  {ip} - {result['message']}")
                    else:
                        secure_hosts.append(f"   ✅ {ip} - {result['message']}")
                else:
                    secure_hosts.append(f"   ❌ {ip} - FAILED ({result['message']})")
            
            if vulnerable_hosts:
                report_content.append("\n🚨 VULNERABLE HOSTS:")
                report_content.extend(vulnerable_hosts)
            
            if secure_hosts:
                report_content.append("\n🔒 SECURE/INACCESSIBLE HOSTS:")
                report_content.extend(secure_hosts)
            report_content.append("")
        
        # Statistics Summary
        report_content.append("SCAN STATISTICS:")
        report_content.append("═" * 80)
        
        # Count successful scans
        fast_success = sum(1 for r in self.scan_results['fast_scan_results'] if r['success'])
        fast_total = len(self.scan_results['fast_scan_results'])
        full_success = sum(1 for r in self.scan_results['full_scan_results'] if r['success'])
        full_total = len(self.scan_results['full_scan_results'])
        udp_success = sum(1 for r in self.scan_results['udp_scan_results'] if r['success'])
        udp_total = len(self.scan_results['udp_scan_results'])
        snmp_success = sum(1 for r in self.scan_results['snmp_scan_results'] if r['success'])
        snmp_total = len(self.scan_results['snmp_scan_results'])
        
        report_content.append(f"Live Hosts Discovered: {len(self.scan_results['live_hosts'])}")
        if fast_total > 0:
            report_content.append(f"Fast Scans: {fast_success}/{fast_total} successful")
        if full_total > 0:
            report_content.append(f"Full Scans: {full_success}/{full_total} successful")
        if udp_total > 0:
            report_content.append(f"UDP Scans: {udp_success}/{udp_total} successful")
        if snmp_total > 0:
            report_content.append(f"SNMP Checks: {snmp_success}/{snmp_total} successful")
        
        # Write consolidated report
        with open(self.consolidated_report, 'w') as f:
            f.write('\n'.join(report_content))
        
        # Write JSON report
        self.scan_results['scan_info']['end_time'] = datetime.now().isoformat()
        with open(self.json_report, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        print_status(f"Consolidated report saved: {Colors.GREEN}{self.consolidated_report}{Colors.END}", "complete")
        print_status(f"JSON report saved: {Colors.GREEN}{self.json_report}{Colors.END}", "complete")
        print_status(f"Detailed log saved: {Colors.GREEN}{self.detailed_log}{Colors.END}", "complete")
    
    def run_comprehensive_scan(self):
        """Run the complete scanning workflow"""
        print_banner()
        print_status("Starting comprehensive network scan...", "info")
        self.log_to_file("Starting comprehensive network scan")
        
        try:
            with open(self.input_file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print_status(f"Input file not found: {self.input_file}", "error")
            return
        
        all_live_hosts = []
        
        if self.skip_ping:
            print_section_header("SKIPPING HOST DISCOVERY (ASSUMING ALL TARGETS ARE LIVE)")
            all_live_hosts = self.expand_targets(targets)
            print_status(f"Treating {Colors.YELLOW}{len(all_live_hosts)}{Colors.END} targets as live hosts", "info")
        else:
            print_section_header("HOST DISCOVERY (using -Pn)", 1)
            
            completed = 0
            for target in targets:
                live_hosts = self.discover_live_hosts(target)
                all_live_hosts.extend(live_hosts)
                completed += 1
                print_progress_bar(completed, len(targets), "Discovery Progress")
        
        # Remove duplicates and save
        all_live_hosts = list(set(all_live_hosts))
        self.scan_results['live_hosts'] = all_live_hosts
        
        with open(self.live_hosts_file, "w") as f:
            for ip in all_live_hosts:
                f.write(ip + "\n")
        
        if not all_live_hosts:
            print_status("No live hosts found. Try using --skip-ping if you know hosts are live.", "error")
            return
        
        print_status(f"Total live hosts discovered: {Colors.GREEN}{len(all_live_hosts)}{Colors.END}", "complete")

        # Fast Scan Stage
        if not self.skip_fast:
            print_section_header("FAST SCAN (TOP 1000 PORTS)", 2)
            
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                future_to_ip = {executor.submit(self.fast_scan_1000, ip): ip for ip in all_live_hosts}
                completed = 0
                
                for future in as_completed(future_to_ip):
                    result = future.result()
                    self.scan_results['fast_scan_results'].append(result)
                    completed += 1
                    print_progress_bar(completed, len(all_live_hosts), "Fast Scan Progress")
        else:
            print_section_header("SKIPPING FAST SCAN")

        # Full Port Scan Stage
        if not self.skip_full:
            print_section_header("FULL PORT SCAN (ALL 65535 PORTS)", 3)
            
            with ThreadPoolExecutor(max_workers=min(5, MAX_THREADS)) as executor:
                future_to_ip = {executor.submit(self.full_port_scan, ip): ip for ip in all_live_hosts}
                completed = 0
                
                for future in as_completed(future_to_ip):
                    result = future.result()
                    self.scan_results['full_scan_results'].append(result)
                    completed += 1
                    print_progress_bar(completed, len(all_live_hosts), "Full Scan Progress")
        else:
            print_section_header("SKIPPING FULL PORT SCAN")

        # UDP Scan Stage
        if not self.skip_udp:
            print_section_header("UDP SCAN", 4)
            
            with ThreadPoolExecutor(max_workers=min(3, MAX_THREADS)) as executor:
                future_to_ip = {executor.submit(self.udp_scan, ip): ip for ip in all_live_hosts}
                completed = 0
                
                for future in as_completed(future_to_ip):
                    result = future.result()
                    self.scan_results['udp_scan_results'].append(result)
                    completed += 1
                    print_progress_bar(completed, len(all_live_hosts), "UDP Scan Progress")
        else:
            print_section_header("SKIPPING UDP SCAN")

        # SNMP Check Stage
        if not self.skip_snmp:
            print_section_header("SNMP CONFIGURATION CHECK", 5)
            
            # Determine SNMP candidates
            snmp_candidates = []
            if self.scan_results['udp_scan_results']:
                for result in self.scan_results['udp_scan_results']:
                    if any("161" in port for port in result['open_ports']):
                        snmp_candidates.append(result['ip'])
            else:
                snmp_candidates = all_live_hosts
            
            if snmp_candidates:
                print_status(f"Checking SNMP on {Colors.YELLOW}{len(snmp_candidates)}{Colors.END} candidates", "info")
                
                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    future_to_ip = {executor.submit(self.snmp_check, ip): ip for ip in snmp_candidates}
                    completed = 0
                    
                    for future in as_completed(future_to_ip):
                        result = future.result()
                        self.scan_results['snmp_scan_results'].append(result)
                        completed += 1
                        print_progress_bar(completed, len(snmp_candidates), "SNMP Check Progress")
            else:
                print_status("No SNMP candidates found (no UDP port 161 open)", "warning")
        else:
            print_section_header("SKIPPING SNMP CHECK")
        
        # Generate comprehensive reports
        print_section_header("GENERATING REPORTS")
        self.generate_consolidated_report()
        
        print_banner()
        print_status(f"🎉 Comprehensive scan completed successfully! 🎉", "complete")
        print_status(f"📁 All results saved in: {Colors.CYAN}{self.output_folder}{Colors.END}", "info")
        print_status(f"📄 Main report: {Colors.GREEN}{self.consolidated_report}{Colors.END}", "info")
        print_status(f"📊 JSON data: {Colors.GREEN}{self.json_report}{Colors.END}", "info")
        print_status(f"📝 Detailed log: {Colors.GREEN}{self.detailed_log}{Colors.END}", "info")

def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}Enhanced Multi-Stage Network Scanner{Colors.END}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.YELLOW}Examples:{Colors.END}
  python3 enhanced_nmap.py targets.txt                    # Run all stages
  python3 enhanced_nmap.py targets.txt --skip-ping       # Skip host discovery
  python3 enhanced_nmap.py targets.txt --skip-full       # Skip full port scan
  python3 enhanced_nmap.py targets.txt --skip-udp --skip-snmp  # TCP only
  python3 enhanced_nmap.py targets.txt --fast-only       # Only fast scan
  python3 enhanced_nmap.py targets.txt --udp-only        # Only UDP scan

{Colors.GREEN}Output Files:{Colors.END}
  • CONSOLIDATED_SCAN_REPORT.txt - Main human-readable report
  • scan_results.json - Machine-readable JSON data
  • detailed_scan.log - Detailed execution log
  • Individual scan files for each host
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
    
    # Convenience options
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
    
    # Validate configuration
    if skip_fast and skip_full and skip_udp:
        print_status("Error: Cannot skip all scan types!", "error")
        sys.exit(1)
    
    # Display configuration
    print_section_header("SCAN CONFIGURATION")
    config_items = [
        ("Host Discovery", "SKIP" if skip_ping else "RUN", "discovery" if not skip_ping else "warning"),
        ("Fast Scan", "SKIP" if skip_fast else "RUN", "scan" if not skip_fast else "warning"),
        ("Full Scan", "SKIP" if skip_full else "RUN", "scan" if not skip_full else "warning"),
        ("UDP Scan", "SKIP" if skip_udp else "RUN", "scan" if not skip_udp else "warning"),
        ("SNMP Check", "SKIP" if skip_snmp else "RUN", "scan" if not skip_snmp else "warning")
    ]
    
    for name, status, status_type in config_items:
        print_status(f"{name:.<20} {status}", status_type, 1)
    
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
