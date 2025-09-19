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
import shutil

# Configuration
MAX_THREADS = 10
TIMEOUT_STANDARD = 600  # 10 minutes for most scans
TIMEOUT_FULL = 1800     # 30 minutes for full port scan

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
║               INFRASTRUCTURE SECURITY SCANNER v3.0                   ║
║           Advanced Internal/External Infrastructure Analysis         ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)

def print_status(message, status_type="info", indent=0):
    """Print enhanced colored status messages"""
    indent_str = "  " * indent
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    status_configs = {
        "info": {"symbol": "ℹ", "color": Colors.BLUE},
        "success": {"symbol": "✓", "color": Colors.GREEN},
        "error": {"symbol": "✗", "color": Colors.RED},
        "warning": {"symbol": "⚠", "color": Colors.YELLOW},
        "progress": {"symbol": "⚡", "color": Colors.CYAN},
        "scan": {"symbol": "🔍", "color": Colors.MAGENTA},
        "complete": {"symbol": "🎯", "color": Colors.GREEN},
        "folder": {"symbol": "📁", "color": Colors.YELLOW},
        "file": {"symbol": "📄", "color": Colors.WHITE}
    }
    
    config = status_configs.get(status_type, status_configs["info"])
    
    formatted_message = (
        f"{indent_str}{config['color']}"
        f"[{config['symbol']}] {Colors.WHITE}{timestamp}{Colors.END} "
        f"{config['color']}{message}{Colors.END}"
    )
    
    print(formatted_message)

def print_section_header(title, scan_type=None):
    """Print colorful section headers"""
    color = Colors.CYAN if scan_type == "external" else Colors.MAGENTA if scan_type == "internal" else Colors.HEADER
    header = f"""
{color}{Colors.BOLD}
{'='*80}
    {title}
{'='*80}
{Colors.END}"""
    print(header)

class SecurityScanner:
    def __init__(self, input_file, scan_mode="external", skip_discovery=False, timing="normal", scan_types=None, custom_ports=None):
        self.input_file = input_file
        self.scan_mode = scan_mode  # "internal" or "external"
        self.skip_discovery = skip_discovery
        self.timing = timing
        self.scan_types = scan_types or []
        self.custom_ports = custom_ports
        
        # Create main output folder
        self.output_folder = f"infra_scan_{scan_mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_folder, exist_ok=True)
        
        # Create subdirectories
        self.hosts_folder = os.path.join(self.output_folder, "hosts")
        self.reports_folder = os.path.join(self.output_folder, "reports")
        self.logs_folder = os.path.join(self.output_folder, "logs")
        
        os.makedirs(self.hosts_folder, exist_ok=True)
        os.makedirs(self.reports_folder, exist_ok=True)
        os.makedirs(self.logs_folder, exist_ok=True)
        
        # Output files
        self.live_hosts_file = os.path.join(self.reports_folder, "live_hosts.txt")
        self.consolidated_report = os.path.join(self.reports_folder, "SECURITY_ASSESSMENT_REPORT.txt")
        self.executive_summary = os.path.join(self.reports_folder, "EXECUTIVE_SUMMARY.txt")
        self.json_report = os.path.join(self.reports_folder, "scan_results.json")
        self.detailed_log = os.path.join(self.logs_folder, "detailed_scan.log")
        self.error_log = os.path.join(self.logs_folder, "errors.log")
        
        self.lock = threading.Lock()
        self.scan_results = {
            'scan_info': {
                'start_time': datetime.now().isoformat(),
                'target_file': input_file,
                'scan_mode': scan_mode,
                'timing': timing,
                'scan_types': scan_types,
                'custom_ports': custom_ports
            },
            'statistics': {
                'total_targets': 0,
                'live_hosts': 0,
                'total_scans': 0,
                'successful_scans': 0,
                'failed_scans': 0
            },
            'live_hosts': [],
            'scan_results': {}
        }
        
        # Initialize log files
        self._initialize_logs()
        
        # Display folder structure
        self._display_folder_structure()

    def _initialize_logs(self):
        """Initialize log files with headers"""
        with open(self.detailed_log, 'w') as f:
            f.write(f"{'='*80}\n")
            f.write(f"Infrastructure Security Scanner - {self.scan_mode.upper()} Scan\n")
            f.write(f"Started: {datetime.now()}\n")
            f.write(f"Timing Profile: {self.timing}\n")
            f.write(f"Scan Types: {', '.join(self.scan_types) if self.scan_types else 'All'}\n")
            f.write(f"{'='*80}\n\n")
        
        with open(self.error_log, 'w') as f:
            f.write("Error Log\n")
            f.write(f"Started: {datetime.now()}\n")
            f.write("="*80 + "\n\n")

    def _display_folder_structure(self):
        """Display the created folder structure"""
        print_status(f"Created output directory: {Colors.GREEN}{self.output_folder}{Colors.END}", "folder")
        print_status("Directory structure:", "info", 1)
        print_status(f"hosts/     - Individual host scan results", "folder", 2)
        print_status(f"reports/   - Consolidated reports and summaries", "folder", 2)
        print_status(f"logs/      - Detailed logs and error tracking", "folder", 2)

    def log_to_file(self, message, log_type="INFO"):
        """Log messages to detailed log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            with open(self.detailed_log, 'a') as f:
                f.write(f"[{timestamp}] [{log_type}] {message}\n")
            
            if log_type == "ERROR":
                with open(self.error_log, 'a') as f:
                    f.write(f"[{timestamp}] {message}\n")

    def get_timing_flag(self):
        """Get nmap timing flag based on timing profile"""
        timing_flags = {
            "slow": "-T1",
            "normal": "-T2",
            "aggressive": "-T4"
        }
        return timing_flags.get(self.timing, "-T2")

    def create_host_folder(self, ip):
        """Create a dedicated folder for each host"""
        # Replace dots with underscores for folder name
        folder_name = ip.replace('.', '_')
        host_folder = os.path.join(self.hosts_folder, folder_name)
        os.makedirs(host_folder, exist_ok=True)
        
        # Create a summary file for this host
        summary_file = os.path.join(host_folder, "HOST_SUMMARY.txt")
        with open(summary_file, 'w') as f:
            f.write(f"{'='*60}\n")
            f.write(f"Host: {ip}\n")
            f.write(f"Scan Started: {datetime.now()}\n")
            f.write(f"Scan Mode: {self.scan_mode}\n")
            f.write(f"Timing: {self.timing}\n")
            f.write(f"{'='*60}\n\n")
        
        return host_folder

    def discover_live_hosts(self, target):
        """Discover live hosts using appropriate method based on scan mode"""
        print_status(f"Discovering live hosts in {Colors.YELLOW}{target}{Colors.END}...", "scan")
        self.log_to_file(f"Starting host discovery for {target}")
        
        live_hosts = []
        
        try:
            timing_flag = self.get_timing_flag()
            
            if self.scan_mode == "internal":
                # For internal, use multiple discovery methods
                cmd = ["nmap", "-sn", timing_flag, "-PS21,22,23,25,80,443,445,3389", 
                       "-PA80,443", "-PU161", target]
            else:
                # For external, use -Pn with quick port check
                cmd = ["nmap", "-Pn", "-sS", timing_flag, "--top-ports", "20", 
                       "--max-retries", "1", target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    if "(" in line and ")" in line:
                        ip = line.split("(")[1].split(")")[0]
                    else:
                        ip = line.split()[-1]
                    
                    # Validate IP
                    if self.is_valid_ip(ip):
                        live_hosts.append(ip)
                        print_status(f"Found live host: {Colors.GREEN}{ip}{Colors.END}", "success", 1)
            
            self.log_to_file(f"Host discovery completed for {target}. Found {len(live_hosts)} hosts")
            return live_hosts
            
        except subprocess.TimeoutExpired:
            print_status(f"Timeout during host discovery for {target}", "error")
            self.log_to_file(f"Host discovery timeout for {target}", "ERROR")
            return []
        except Exception as e:
            print_status(f"Error in host discovery: {e}", "error")
            self.log_to_file(f"Host discovery error: {e}", "ERROR")
            return []

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

    def run_nmap_command(self, ip, command_desc, nmap_args, output_suffix, host_folder):
        """Generic function to run nmap commands and save results"""
        print_status(f"Running {command_desc} on {Colors.CYAN}{ip}{Colors.END}...", "scan", 1)
        self.log_to_file(f"Starting {command_desc} for {ip}")
        
        try:
            # Add timing flag to nmap args
            timing_flag = self.get_timing_flag()
            cmd = ["nmap", "-Pn", timing_flag] + nmap_args + [ip]
            
            # Set timeout based on scan type
            timeout = TIMEOUT_FULL if "full" in output_suffix else TIMEOUT_STANDARD
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Save output to host-specific folder
            output_file = os.path.join(host_folder, f"{output_suffix}_scan.txt")
            
            with open(output_file, 'w') as f:
                f.write(f"{'='*80}\n")
                f.write(f"{command_desc.upper()} RESULTS FOR {ip}\n")
                f.write(f"Command: {' '.join(cmd)}\n")
                f.write(f"Timestamp: {datetime.now()}\n")
                f.write(f"{'='*80}\n\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n\nSTDERR:\n")
                    f.write(result.stderr)
            
            # Parse for findings
            findings = self.parse_nmap_output(result.stdout, command_desc)
            
            if findings:
                print_status(f"Found {len(findings)} findings in {command_desc}", "warning", 2)
                # Save findings to a separate file
                findings_file = os.path.join(host_folder, f"{output_suffix}_findings.txt")
                with open(findings_file, 'w') as f:
                    f.write(f"FINDINGS FROM {command_desc.upper()}\n")
                    f.write("="*60 + "\n\n")
                    for finding in findings:
                        f.write(f"• {finding}\n")
            
            self.log_to_file(f"Completed {command_desc} for {ip}")
            self.scan_results['statistics']['successful_scans'] += 1
            
            return {
                'success': True,
                'output': result.stdout,
                'findings': findings,
                'output_file': output_file
            }
            
        except subprocess.TimeoutExpired:
            print_status(f"Timeout during {command_desc} for {ip}", "error", 2)
            self.log_to_file(f"Timeout in {command_desc} for {ip}", "ERROR")
            self.scan_results['statistics']['failed_scans'] += 1
            return {'success': False, 'error': 'timeout', 'findings': []}
        except Exception as e:
            print_status(f"Error in {command_desc}: {e}", "error", 2)
            self.log_to_file(f"Error in {command_desc} for {ip}: {e}", "ERROR")
            self.scan_results['statistics']['failed_scans'] += 1
            return {'success': False, 'error': str(e), 'findings': []}

    def parse_nmap_output(self, output, scan_type):
        """Parse nmap output for important findings"""
        findings = []
        
        # Look for vulnerabilities
        vuln_keywords = ['VULNERABLE', 'vulnerable', 'LIKELY VULNERABLE', 'MS17-010', 
                        'EternalBlue', 'Heartbleed', 'CVE-', 'WEAK', 'ANONYMOUS',
                        'null session', 'Obsolete', 'deprecated', 'unencrypted']
        
        for line in output.splitlines():
            # Check for vulnerability keywords
            for keyword in vuln_keywords:
                if keyword in line:
                    findings.append(f"[VULN] {line.strip()}")
                    break
            
            # Check for open ports
            if "/tcp" in line and "open" in line:
                findings.append(f"[OPEN TCP] {line.strip()}")
            elif "/udp" in line and "open" in line:
                findings.append(f"[OPEN UDP] {line.strip()}")
            
            # Check for service versions
            if "Service Info:" in line:
                findings.append(f"[SERVICE] {line.strip()}")
            
            # Check for OS detection
            if "OS details:" in line or "Running:" in line:
                findings.append(f"[OS] {line.strip()}")
        
        return findings

    def get_scan_commands(self):
        """Get scan commands based on scan mode and selected scan types"""
        all_commands = {
            'internal': {
                'ad_services': {
                    'name': 'AD Service Discovery',
                    'args': ['-sV', '-sC', '-p', '88,135,139,389,445,464,636,3268,3269'],
                    'suffix': 'ad_services'
                },
                'smb_scan': {
                    'name': 'SMB Enumeration & Vulnerabilities',
                    'args': ['--script', 'smb-enum-*,smb-vuln-*,smb-os-discovery', '-p139,445'],
                    'suffix': 'smb'
                },
                'ldap_kerb': {
                    'name': 'LDAP/Kerberos Enumeration',
                    'args': ['-p', '88,389,636', '--script', 'ldap-*,krb5-enum-users'],
                    'suffix': 'ldap_kerberos'
                },
                'msrpc': {
                    'name': 'MS-RPC Enumeration',
                    'args': ['-p', '135,593', '--script', 'msrpc-enum,rpc-grind'],
                    'suffix': 'msrpc'
                },
                'web_services': {
                    'name': 'Internal Web Services',
                    'args': ['-p', '80,443,8080,8443', '--script', 'http-title,http-methods,http-enum'],
                    'suffix': 'web'
                }
            },
            'external': {
                'top_ports': {
                    'name': 'Top Ports Scan',
                    'args': ['-sV', '--top-ports', '1000'],
                    'suffix': 'top_ports'
                },
                'full_scan': {
                    'name': 'Full Port Scan',
                    'args': ['-sV', '-p-'],
                    'suffix': 'full_ports'
                },
                'smb_scan': {
                    'name': 'SMB Vulnerability Scan',
                    'args': ['--script', 'smb-vuln*', '-p139,445'],
                    'suffix': 'smb_vuln'
                },
                'ssl_scan': {
                    'name': 'SSL/TLS Security Scan',
                    'args': ['-p', '443,636,993,465,8443', '--script', 'ssl-*,tls-*'],
                    'suffix': 'ssl_tls'
                },
                'web_scan': {
                    'name': 'Web Application Scan',
                    'args': ['-p', '80,443,8080,8443', '--script', 'http-*'],
                    'suffix': 'web_app'
                },
                'vuln_scan': {
                    'name': 'General Vulnerability Scan',
                    'args': ['--script', 'vuln', '-sV'],
                    'suffix': 'vulnerabilities'
                }
            }
        }
        
        # If custom ports specified, create custom scan
        if self.custom_ports:
            return [{
                'name': f'Custom Port Scan ({self.custom_ports})',
                'args': ['-sV', '-sC', '-p', self.custom_ports],
                'suffix': 'custom_ports'
            }]
        
        # Get commands based on scan mode
        mode_commands = all_commands.get(self.scan_mode, all_commands['external'])
        
        # If specific scan types requested, filter
        if self.scan_types:
            selected_commands = []
            for scan_type in self.scan_types:
                if scan_type in mode_commands:
                    selected_commands.append(mode_commands[scan_type])
            return selected_commands if selected_commands else list(mode_commands.values())
        
        # Return all commands for the mode
        return list(mode_commands.values())

    def scan_infrastructure(self, hosts):
        """Run infrastructure scans based on mode"""
        scan_type = "internal" if self.scan_mode == "internal" else "external"
        print_section_header(f"{scan_type.upper()} INFRASTRUCTURE SCANNING", scan_type)
        
        scan_commands = self.get_scan_commands()
        
        print_status(f"Will run {len(scan_commands)} scan types per host", "info")
        self.scan_results['statistics']['total_scans'] = len(hosts) * len(scan_commands)
        
        for host in hosts:
            print_status(f"Scanning host: {Colors.YELLOW}{host}{Colors.END}", "info")
            
            # Create host-specific folder
            host_folder = self.create_host_folder(host)
            print_status(f"Host folder: {Colors.CYAN}{host_folder}{Colors.END}", "folder", 1)
            
            host_results = {}
            
            for scan in scan_commands:
                result = self.run_nmap_command(
                    host,
                    scan['name'],
                    scan['args'],
                    scan['suffix'],
                    host_folder
                )
                host_results[scan['name']] = result
            
            # Update host summary
            self.update_host_summary(host, host_folder, host_results)
            
            self.scan_results['scan_results'][host] = host_results
            
            # Add delay between hosts if in slow mode
            if self.timing == "slow" and host != hosts[-1]:
                print_status("Waiting 30 seconds before next host (slow mode)...", "info", 1)
                time.sleep(30)

    def update_host_summary(self, host, host_folder, scan_results):
        """Update the host summary file with scan results"""
        summary_file = os.path.join(host_folder, "HOST_SUMMARY.txt")
        
        with open(summary_file, 'a') as f:
            f.write("\nSCAN RESULTS SUMMARY\n")
            f.write("="*60 + "\n\n")
            
            total_findings = 0
            critical_findings = []
            open_ports = []
            
            for scan_name, result in scan_results.items():
                f.write(f"\n[{scan_name}]\n")
                f.write("-"*40 + "\n")
                
                if result['success']:
                    f.write(f"Status: SUCCESS\n")
                    f.write(f"Findings: {len(result['findings'])}\n")
                    
                    if result['findings']:
                        f.write("\nKey Findings:\n")
                        for finding in result['findings'][:5]:  # First 5 findings
                            f.write(f"  • {finding}\n")
                        if len(result['findings']) > 5:
                            f.write(f"  ... and {len(result['findings']) - 5} more\n")
                    
                    total_findings += len(result['findings'])
                    
                    # Categorize findings
                    for finding in result['findings']:
                        if '[VULN]' in finding or 'CVE' in finding:
                            critical_findings.append(finding)
                        if '[OPEN TCP]' in finding or '[OPEN UDP]' in finding:
                            open_ports.append(finding)
                else:
                    f.write(f"Status: FAILED\n")
                    f.write(f"Error: {result.get('error', 'Unknown')}\n")
            
            # Write summary statistics
            f.write("\n" + "="*60 + "\n")
            f.write("STATISTICS\n")
            f.write("="*60 + "\n")
            f.write(f"Total Findings: {total_findings}\n")
            f.write(f"Critical Issues: {len(critical_findings)}\n")
            f.write(f"Open Ports Found: {len(open_ports)}\n")
            f.write(f"Scan Completed: {datetime.now()}\n")

    def generate_security_report(self):
        """Generate comprehensive security reports"""
        print_status("Generating security reports...", "progress")
        
        # Generate main security report
        self.generate_detailed_report()
        
        # Generate executive summary
        self.generate_executive_summary()
        
        # Save JSON report
        self.save_json_report()
        
        print_status(f"Security report saved: {Colors.GREEN}{self.consolidated_report}{Colors.END}", "complete")
        print_status(f"Executive summary saved: {Colors.GREEN}{self.executive_summary}{Colors.END}", "complete")
        print_status(f"JSON report saved: {Colors.GREEN}{self.json_report}{Colors.END}", "complete")

    def generate_detailed_report(self):
        """Generate detailed security assessment report"""
        report_content = []
        
        # Header
        report_content.append("═" * 100)
        report_content.append(f"           INFRASTRUCTURE SECURITY ASSESSMENT REPORT")
        report_content.append(f"                    {self.scan_mode.upper()} INFRASTRUCTURE")
        report_content.append("═" * 100)
        report_content.append(f"\nScan Information:")
        report_content.append(f"  • Started: {self.scan_results['scan_info']['start_time']}")
        report_content.append(f"  • Completed: {datetime.now().isoformat()}")
        report_content.append(f"  • Target File: {self.scan_results['scan_info']['target_file']}")
        report_content.append(f"  • Scan Mode: {self.scan_mode}")
        report_content.append(f"  • Timing Profile: {self.timing}")
        report_content.append(f"  • Total Hosts Scanned: {len(self.scan_results['live_hosts'])}")
        report_content.append(f"  • Total Scans Run: {self.scan_results['statistics']['total_scans']}")
        report_content.append(f"  • Successful Scans: {self.scan_results['statistics']['successful_scans']}")
        report_content.append(f"  • Failed Scans: {self.scan_results['statistics']['failed_scans']}")
        
        # Categorize findings
        critical_findings = []
        high_findings = []
        medium_findings = []
        low_findings = []
        
        # Detailed host results
        report_content.append("\n" + "═" * 100)
        report_content.append("DETAILED HOST RESULTS")
        report_content.append("═" * 100)
        
        for host, scans in self.scan_results['scan_results'].items():
            report_content.append(f"\n{'='*80}")
            report_content.append(f"HOST: {host}")
            report_content.append(f"{'='*80}")
            
            host_folder = os.path.join(self.hosts_folder, host.replace('.', '_'))
            report_content.append(f"Results Location: {host_folder}")
            
            for scan_name, scan_result in scans.items():
                report_content.append(f"\n[{scan_name}]")
                report_content.append("-" * 40)
                
                if scan_result['success']:
                    if scan_result['findings']:
                        report_content.append(f"Status: ⚠ Issues Found ({len(scan_result['findings'])} findings)")
                        
                        # Show first 10 findings
                        for finding in scan_result['findings'][:10]:
                            report_content.append(f"  • {finding}")
                            
                            # Categorize findings
                            if any(word in finding.upper() for word in ['VULNERABLE', 'CVE', 'MS17-010', 'ETERNALBLUE']):
                                critical_findings.append(f"{host}: {finding}")
                            elif any(word in finding.upper() for word in ['WEAK', 'ANONYMOUS', 'NULL']):
                                high_findings.append(f"{host}: {finding}")
                            elif '[OPEN TCP]' in finding or '[OPEN UDP]' in finding:
                                medium_findings.append(f"{host}: {finding}")
                            else:
                                low_findings.append(f"{host}: {finding}")
                        
                        if len(scan_result['findings']) > 10:
                            report_content.append(f"  ... and {len(scan_result['findings']) - 10} more findings")
                            report_content.append(f"  See full results in: {scan_result.get('output_file', 'N/A')}")
                    else:
                        report_content.append("Status: ✓ No significant findings")
                else:
                    report_content.append(f"Status: ✗ Scan Failed")
                    report_content.append(f"  Error: {scan_result.get('error', 'Unknown error')}")
        
        # Risk Summary
        report_content.append("\n" + "═" * 100)
        report_content.append("RISK SUMMARY")
        report_content.append("═" * 100)
        
        if critical_findings:
            report_content.append(f"\n🔴 CRITICAL RISK ({len(critical_findings)} findings)")
            report_content.append("These require immediate attention:")
            for finding in critical_findings[:10]:
                report_content.append(f"  • {finding}")
        
        if high_findings:
            report_content.append(f"\n🟠 HIGH RISK ({len(high_findings)} findings)")
            report_content.append("These should be addressed urgently:")
            for finding in high_findings[:10]:
                report_content.append(f"  • {finding}")
        
        if medium_findings:
            report_content.append(f"\n🟡 MEDIUM RISK ({len(medium_findings)} findings)")
            report_content.append("These should be reviewed and remediated:")
            for finding in medium_findings[:10]:
                report_content.append(f"  • {finding}")
        
        # Recommendations
        report_content.append("\n" + "═" * 100)
        report_content.append("RECOMMENDATIONS")
        report_content.append("═" * 100)
        
        if self.scan_mode == "internal":
            report_content.append("\nActive Directory & Internal Infrastructure:")
            report_content.append("  1. Review and harden Active Directory configurations")
            report_content.append("  2. Implement network segmentation between critical services")
            report_content.append("  3. Disable unnecessary services and ports")
            report_content.append("  4. Enable SMB signing and disable SMBv1")
            report_content.append("  5. Implement LDAPS (LDAP over SSL) for secure directory services")
            report_content.append("  6. Review and restrict NTLM authentication")
            report_content.append("  7. Implement PowerShell logging and monitoring")
            report_content.append("  8. Regular security updates and patch management")
        else:
            report_content.append("\nExternal Infrastructure:")
            report_content.append("  1. Minimize external attack surface by closing unnecessary ports")
            report_content.append("  2. Implement Web Application Firewall (WAF) for web services")
            report_content.append("  3. Ensure all SSL/TLS configurations use strong ciphers (TLS 1.2+)")
            report_content.append("  4. Implement rate limiting and DDoS protection")
            report_content.append("  5. Use VPN or bastion hosts for administrative access")
            report_content.append("  6. Regular vulnerability assessments and penetration testing")
            report_content.append("  7. Implement intrusion detection/prevention systems (IDS/IPS)")
            report_content.append("  8. Enable comprehensive logging and monitoring")
        
        # Write report to file
        with open(self.consolidated_report, 'w') as f:
            f.write('\n'.join(report_content))
    
    def generate_executive_summary(self):
        """Generate executive summary for management"""
        summary_content = []
        
        # Calculate statistics
        total_findings = sum(
            len(scan['findings']) 
            for host_scans in self.scan_results['scan_results'].values() 
            for scan in host_scans.values() 
            if scan['success']
        )
        
        critical_count = sum(
            1 for host_scans in self.scan_results['scan_results'].values()
            for scan in host_scans.values()
            if scan['success']
            for finding in scan['findings']
            if any(word in finding.upper() for word in ['VULNERABLE', 'CVE', 'MS17-010'])
        )
        
        # Header
        summary_content.append("═" * 80)
        summary_content.append("              EXECUTIVE SUMMARY")
        summary_content.append("         Infrastructure Security Assessment")
        summary_content.append("═" * 80)
        summary_content.append(f"\nAssessment Date: {datetime.now().strftime('%B %d, %Y')}")
        summary_content.append(f"Infrastructure Type: {self.scan_mode.capitalize()}")
        summary_content.append(f"Assessment Duration: {self._calculate_duration()}")
        
        # Key Metrics
        summary_content.append("\n" + "─" * 80)
        summary_content.append("KEY METRICS")
        summary_content.append("─" * 80)
        summary_content.append(f"  • Hosts Assessed: {len(self.scan_results['live_hosts'])}")
        summary_content.append(f"  • Total Security Scans: {self.scan_results['statistics']['total_scans']}")
        summary_content.append(f"  • Success Rate: {self._calculate_success_rate():.1f}%")
        summary_content.append(f"  • Total Findings: {total_findings}")
        summary_content.append(f"  • Critical Issues: {critical_count}")
        
        # Risk Assessment
        summary_content.append("\n" + "─" * 80)
        summary_content.append("OVERALL RISK ASSESSMENT")
        summary_content.append("─" * 80)
        
        if critical_count > 5:
            risk_level = "CRITICAL"
            risk_color = "🔴"
        elif critical_count > 0:
            risk_level = "HIGH"
            risk_color = "🟠"
        elif total_findings > 20:
            risk_level = "MEDIUM"
            risk_color = "🟡"
        else:
            risk_level = "LOW"
            risk_color = "🟢"
        
        summary_content.append(f"\n  {risk_color} Overall Risk Level: {risk_level}")
        
        # Key Findings Summary
        summary_content.append("\n" + "─" * 80)
        summary_content.append("KEY FINDINGS")
        summary_content.append("─" * 80)
        
        if critical_count > 0:
            summary_content.append(f"\n  • {critical_count} critical vulnerabilities identified")
            summary_content.append("    - Immediate remediation required")
            summary_content.append("    - May include known exploitable vulnerabilities")
        
        open_ports_count = sum(
            1 for host_scans in self.scan_results['scan_results'].values()
            for scan in host_scans.values()
            if scan['success']
            for finding in scan['findings']
            if '[OPEN' in finding
        )
        
        if open_ports_count > 0:
            summary_content.append(f"\n  • {open_ports_count} open ports discovered")
            summary_content.append("    - Review for business necessity")
            summary_content.append("    - Consider implementing access controls")
        
        # Immediate Actions Required
        summary_content.append("\n" + "─" * 80)
        summary_content.append("IMMEDIATE ACTIONS REQUIRED")
        summary_content.append("─" * 80)
        
        if critical_count > 0:
            summary_content.append("\n  1. Address critical vulnerabilities immediately")
            summary_content.append("  2. Implement emergency patching procedures")
            summary_content.append("  3. Review and restrict network access to vulnerable systems")
        else:
            summary_content.append("\n  1. Review and validate all findings")
            summary_content.append("  2. Prioritize remediation based on risk")
            summary_content.append("  3. Schedule regular security assessments")
        
        # Next Steps
        summary_content.append("\n" + "─" * 80)
        summary_content.append("RECOMMENDED NEXT STEPS")
        summary_content.append("─" * 80)
        summary_content.append("\n  1. Review detailed technical report with IT team")
        summary_content.append("  2. Create remediation plan with timeline")
        summary_content.append("  3. Allocate resources for security improvements")
        summary_content.append("  4. Schedule follow-up assessment after remediation")
        summary_content.append("  5. Consider security awareness training for staff")
        
        # Footer
        summary_content.append("\n" + "═" * 80)
        summary_content.append("For detailed technical findings, see SECURITY_ASSESSMENT_REPORT.txt")
        summary_content.append("For raw scan data, see individual host folders in hosts/")
        summary_content.append("═" * 80)
        
        # Write summary to file
        with open(self.executive_summary, 'w') as f:
            f.write('\n'.join(summary_content))
    
    def save_json_report(self):
        """Save scan results in JSON format"""
        self.scan_results['scan_info']['end_time'] = datetime.now().isoformat()
        self.scan_results['scan_info']['duration'] = self._calculate_duration()
        
        # Add summary statistics
        self.scan_results['summary'] = {
            'total_findings': sum(
                len(scan['findings']) 
                for host_scans in self.scan_results['scan_results'].values() 
                for scan in host_scans.values() 
                if scan['success']
            ),
            'hosts_with_issues': sum(
                1 for host_scans in self.scan_results['scan_results'].values()
                if any(scan['success'] and scan['findings'] for scan in host_scans.values())
            ),
            'success_rate': self._calculate_success_rate()
        }
        
        with open(self.json_report, 'w') as f:
            json.dump(self.scan_results, f, indent=2, default=str)
    
    def _calculate_duration(self):
        """Calculate scan duration"""
        start_time = datetime.fromisoformat(self.scan_results['scan_info']['start_time'])
        duration = datetime.now() - start_time
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def _calculate_success_rate(self):
        """Calculate scan success rate"""
        total = self.scan_results['statistics']['total_scans']
        successful = self.scan_results['statistics']['successful_scans']
        
        if total == 0:
            return 0.0
        return (successful / total) * 100
    
    def run(self):
        """Main execution flow"""
        print_banner()
        
        # Display scan configuration
        print_status(f"Scan mode: {Colors.YELLOW}{self.scan_mode.upper()}{Colors.END} Infrastructure", "info")
        print_status(f"Timing profile: {Colors.YELLOW}{self.timing}{Colors.END}", "info")
        if self.scan_types:
            print_status(f"Scan types: {Colors.YELLOW}{', '.join(self.scan_types)}{Colors.END}", "info")
        if self.custom_ports:
            print_status(f"Custom ports: {Colors.YELLOW}{self.custom_ports}{Colors.END}", "info")
        
        # Load targets
        try:
            with open(self.input_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.scan_results['statistics']['total_targets'] = len(targets)
        except FileNotFoundError:
            print_status(f"Input file not found: {self.input_file}", "error")
            return
        
        print_status(f"Loaded {len(targets)} targets from {self.input_file}", "info")
        
        # Host discovery
        all_live_hosts = []
        
        if self.skip_discovery:
            print_section_header("SKIPPING HOST DISCOVERY")
            all_live_hosts = targets
            print_status(f"Treating all {len(targets)} targets as live hosts", "info")
        else:
            print_section_header("HOST DISCOVERY PHASE")
            for target in targets:
                live_hosts = self.discover_live_hosts(target)
                all_live_hosts.extend(live_hosts)
        
        # Remove duplicates
        all_live_hosts = list(set(all_live_hosts))
        self.scan_results['live_hosts'] = all_live_hosts
        self.scan_results['statistics']['live_hosts'] = len(all_live_hosts)
        
        # Save live hosts
        with open(self.live_hosts_file, 'w') as f:
            for host in all_live_hosts:
                f.write(f"{host}\n")
        
        if not all_live_hosts:
            print_status("No live hosts found. Exiting.", "error")
            return
        
        print_status(f"Total live hosts to scan: {Colors.GREEN}{len(all_live_hosts)}{Colors.END}", "info")
        
        # Run infrastructure scans
        self.scan_infrastructure(all_live_hosts)
        
        # Generate reports
        print_section_header("GENERATING REPORTS")
        self.generate_security_report()
        
        # Summary
        print("")
        print_section_header("SCAN COMPLETE")
        print_status(f"Output directory: {Colors.CYAN}{self.output_folder}{Colors.END}", "folder")
        print("")
        print_status("Generated Files:", "info")
        print_status(f"Executive Summary: {Colors.GREEN}{self.executive_summary}{Colors.END}", "file", 1)
        print_status(f"Detailed Report: {Colors.GREEN}{self.consolidated_report}{Colors.END}", "file", 1)
        print_status(f"JSON Data: {Colors.GREEN}{self.json_report}{Colors.END}", "file", 1)
        print_status(f"Scan Logs: {Colors.GREEN}{self.detailed_log}{Colors.END}", "file", 1)
        print("")
        print_status(f"Individual host results in: {Colors.CYAN}{self.hosts_folder}{Colors.END}", "folder")
        print_status(f"Success rate: {Colors.GREEN}{self._calculate_success_rate():.1f}%{Colors.END}", "success")
        print_status(f"Duration: {Colors.YELLOW}{self._calculate_duration()}{Colors.END}", "info")

def main():
    parser = argparse.ArgumentParser(
        description='Infrastructure Security Scanner v3.0 - Advanced Network Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 infra_scanner.py targets.txt                      # Interactive mode
  python3 infra_scanner.py targets.txt --internal           # Internal/AD scan
  python3 infra_scanner.py targets.txt --external --slow    # Stealthy external scan
  python3 infra_scanner.py targets.txt --top-ports --aggressive  # Fast top ports scan
  python3 infra_scanner.py targets.txt --ports "22,80,443"  # Custom ports
  python3 infra_scanner.py targets.txt --smb-scan --vuln-scan  # SMB + vulnerability scan

Output Structure:
  infra_scan_[mode]_[timestamp]/
    ├── hosts/          # Individual host folders with scan results
    ├── reports/        # Consolidated reports and summaries
    └── logs/           # Detailed scan and error logs
        """
    )
    
    parser.add_argument('targets_file', help='File containing target IPs/ranges (one per line)')
    
    # Scan modes
    mode_group = parser.add_argument_group('Scan Modes')
    mode_group.add_argument('--internal', action='store_true', help='Internal/AD infrastructure scan')
    mode_group.add_argument('--external', action='store_true', help='External infrastructure scan')
    
    # Timing profiles
    timing_group = parser.add_argument_group('Timing Profiles')
    timing_group.add_argument('--slow', action='store_true', help='Slow/stealthy scanning (T1)')
    timing_group.add_argument('--normal', action='store_true', help='Normal speed (T2, default)')
    timing_group.add_argument('--aggressive', action='store_true', help='Fast aggressive scanning (T4)')
    
    # Scan types
    scan_group = parser.add_argument_group('Scan Types')
    scan_group.add_argument('--top-ports', action='store_true', help='Scan top 1000 ports')
    scan_group.add_argument('--full-scan', action='store_true', help='Full port scan (all 65535)')
    scan_group.add_argument('--smb-scan', action='store_true', help='SMB/NetBIOS enumeration')
    scan_group.add_argument('--ssl-scan', action='store_true', help='SSL/TLS security assessment')
    scan_group.add_argument('--web-scan', action='store_true', help='Web application scanning')
    scan_group.add_argument('--vuln-scan', action='store_true', help='Vulnerability scanning')
    scan_group.add_argument('--ports', metavar='PORTS', help='Custom ports (e.g., "22,80,443")')
    
    # Additional options
    parser.add_argument('--skip-discovery', action='store_true', help='Skip host discovery phase')
    
    args = parser.parse_args()
    
    # Determine scan mode
    if args.internal and args.external:
        print_status("Error: Cannot specify both --internal and --external", "error")
        sys.exit(1)
    elif args.internal:
        scan_mode = "internal"
    elif args.external:
        scan_mode = "external"
    else:
        # Interactive mode
        print_banner()
        print_status("Please select scan type:", "info")
        print(f"  {Colors.CYAN}1{Colors.END}) Internal/AD Infrastructure")
        print(f"  {Colors.CYAN}2{Colors.END}) External Infrastructure")
        
        while True:
            choice = input(f"\n{Colors.YELLOW}Enter choice (1 or 2): {Colors.END}").strip()
            if choice == "1":
                scan_mode = "internal"
                break
            elif choice == "2":
                scan_mode = "external"
                break
            else:
                print_status("Invalid choice. Please enter 1 or 2.", "error")
    
    # Determine timing profile
    if sum([args.slow, args.normal, args.aggressive]) > 1:
        print_status("Error: Can only specify one timing profile", "error")
        sys.exit(1)
    elif args.slow:
        timing = "slow"
    elif args.aggressive:
        timing = "aggressive"
    else:
        timing = "normal"
    
    # Collect scan types
    scan_types = []
    if args.top_ports:
        scan_types.append('top_ports')
    if args.full_scan:
        scan_types.append('full_scan')
    if args.smb_scan:
        scan_types.append('smb_scan')
    if args.ssl_scan:
        scan_types.append('ssl_scan')
    if args.web_scan:
        scan_types.append('web_scan')
    if args.vuln_scan:
        scan_types.append('vuln_scan')
    
    # Validate input file
    if not os.path.exists(args.targets_file):
        print_status(f"Input file not found: {args.targets_file}", "error")
        sys.exit(1)
    
    # Create and run scanner
    scanner = SecurityScanner(
        args.targets_file,
        scan_mode=scan_mode,
        skip_discovery=args.skip_discovery,
        timing=timing,
        scan_types=scan_types if scan_types else None,
        custom_ports=args.ports
    )
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n")
        print_status("Scan interrupted by user", "warning")
        sys.exit(1)
    except Exception as e:
        print_status(f"Unexpected error: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()
