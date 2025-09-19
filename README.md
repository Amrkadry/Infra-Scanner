# Infra Scanner - Advanced Infrastructure Security Assessment Tool

A comprehensive Python-based infrastructure security scanner designed for thorough assessment of both internal and external network infrastructure. This tool provides intelligent host discovery, multi-stage scanning with customizable timing profiles, and detailed vulnerability assessment capabilities.

![Infra Scanner Banner](https://img.shields.io/badge/Version-3.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.6%2B-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🎯 Key Features

### Infrastructure Modes
- **Internal Infrastructure Scanning** - Optimized for Active Directory and internal network assessment
- **External Infrastructure Scanning** - Controlled scanning for internet-facing assets with timing controls

### Advanced Scanning Capabilities
- ✅ **Flexible Timing Profiles** - Slow/stealthy, normal, or aggressive scanning modes
- ✅ **Modular Scan Types** - Choose specific scan modules based on requirements
- ✅ **Switch Explanations** - Automatic explanation of Nmap switches being used
- ✅ **Smart Host Discovery** - Firewall-aware discovery techniques
- ✅ **Comprehensive Reporting** - Multiple output formats with severity classification
- ✅ **Custom Port Specifications** - Define specific ports to scan
- ✅ **Progress Tracking** - Real-time colored status updates with timing information

## 📋 Requirements

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap python3 python3-pip

# CentOS/RHEL/Fedora
sudo yum install nmap python3
# or
sudo dnf install nmap python3

# macOS
brew install nmap python3

# Windows (WSL recommended)
# Install WSL first, then follow Ubuntu/Debian instructions
```

### Python Requirements
- Python 3.6 or higher
- No additional pip packages required (uses standard library only)

## 🔧 Installation

1. **Clone or download the scanner:**
```bash
# If you have git
git clone https://github.com/Amrkadry/infra-scanner.git
cd infra-scanner

# Or download directly
wget https://raw.githubusercontent.com/Amrkadry/infra-scanner/main/infra_scanner.py
```

2. **Make the script executable:**
```bash
chmod +x infra_scanner.py
```

3. **Verify dependencies:**
```bash
# Check Python version
python3 --version

# Check Nmap installation
nmap --version
```

## 📖 Usage Guide

### Basic Usage

```bash
# Interactive mode - prompts for scan type
python3 infra_scanner.py targets.txt

# Internal infrastructure scan
python3 infra_scanner.py targets.txt --internal

# External infrastructure scan
python3 infra_scanner.py targets.txt --external
```

### Target File Format

Create a `targets.txt` file with one target per line:

```
192.168.1.1
192.168.1.0/24
10.0.0.1-10
172.16.1.100
external.example.com
```

Supported formats:
- Individual IPs: `192.168.1.1`
- CIDR notation: `192.168.1.0/24`
- IP ranges: `192.168.1.1-10`
- Hostnames: `example.com`

## ⚙️ Command Line Options

### Scan Modes
| Option | Description |
|--------|-------------|
| `--internal` | Perform internal/AD infrastructure scan |
| `--external` | Perform external infrastructure scan |

### Timing Profiles
| Option | Description | Nmap Template | Use Case |
|--------|-------------|---------------|----------|
| `--slow` | Slow, stealthy scanning | T1 (Sneaky) | Evading IDS/IPS, minimal network impact |
| `--normal` | Normal speed (default) | T2 (Polite) | Balanced speed and stealth |
| `--aggressive` | Fast aggressive scanning | T4 (Aggressive) | Quick results, less concerned about detection |

### Scan Types
| Option | Description | Ports/Scripts |
|--------|-------------|---------------|
| `--top-ports` | Quick scan of top 1000 ports | Top 1000 TCP ports |
| `--smb-scan` | SMB/NetBIOS enumeration | 139,445 + SMB scripts |
| `--ssl-scan` | SSL/TLS assessment | 443,636,993,465,8443 + SSL scripts |
| `--web-scan` | Web application scanning | 80,443,8080,8443 + HTTP scripts |
| `--vuln-scan` | Comprehensive vulnerability scan | All ports + vuln scripts |
| `--full-scan` | Complete port scan | All 65535 ports |
| `--ports PORTS` | Custom port specification | User-defined ports |

### Additional Options
| Option | Description |
|--------|-------------|
| `--skip-discovery` | Skip host discovery (treat all as live) |

## 💡 Usage Examples

### Quick Assessment Scenarios

#### 1. Fast External Assessment
```bash
# Quick top ports scan with normal timing
python3 infra_scanner.py targets.txt --external --top-ports
```

#### 2. Stealthy External Scan
```bash
# Slow, careful scanning to avoid detection
python3 infra_scanner.py targets.txt --external --slow --top-ports
```

#### 3. Internal AD Assessment
```bash
# Comprehensive internal scan with SMB focus
python3 infra_scanner.py targets.txt --internal --smb-scan
```

#### 4. Web Application Security
```bash
# Focus on web services and SSL/TLS
python3 infra_scanner.py targets.txt --external --web-scan --ssl-scan
```

#### 5. Full Vulnerability Assessment
```bash
# Complete scan with all vulnerability checks
python3 infra_scanner.py targets.txt --external --vuln-scan --full-scan
```

#### 6. Custom Port Scanning
```bash
# Scan specific ports only
python3 infra_scanner.py targets.txt --ports "22,80,443,3389,8080"
```

#### 7. Known Live Hosts
```bash
# Skip discovery when hosts don't respond to ping
python3 infra_scanner.py targets.txt --skip-discovery --smb-scan
```

#### 8. Aggressive Internal Scan
```bash
# Fast internal scan when detection isn't a concern
python3 infra_scanner.py targets.txt --internal --aggressive --full-scan
```

## 📊 Nmap Switches Explained

The scanner automatically explains the Nmap switches being used. Here are the common ones:

### Discovery Switches
- `-Pn`: Skip host discovery (treat all as online)
- `-PS`: TCP SYN ping on specified ports
- `-PA`: TCP ACK ping on specified ports
- `-PU`: UDP ping on specified ports
- `-sn`: No port scan (discovery only)

### Scan Types
- `-sS`: TCP SYN scan (stealth scan)
- `-sV`: Version detection
- `-sC`: Run default NSE scripts
- `-sU`: UDP scan

### Timing Templates
- `-T0`: Paranoid (5 minutes between probes)
- `-T1`: Sneaky (15 seconds between probes)
- `-T2`: Polite (0.4 seconds between probes)
- `-T3`: Normal (default)
- `-T4`: Aggressive (faster)
- `-T5`: Insane (fastest, may miss results)


## 📁 Output Structure

The scanner creates a timestamped output folder:

```
infra_scan_[mode]_[timestamp]/
├── live_hosts.txt                 # List of discovered live hosts
├── INFRA_SECURITY_REPORT.txt      # Main security report
├── scan_results.json              # JSON formatted results
├── detailed_scan.log              # Detailed scan logs
└── [IP]_[scan_type].txt          # Individual host results
    ├── 192_168_1_1_top_ports.txt
    ├── 192_168_1_1_smb_vuln.txt
    ├── 192_168_1_1_ssl_tls.txt
    └── ...
```

### Report Contents

#### Security Report (INFRA_SECURITY_REPORT.txt)
- Executive summary
- Scan configuration details
- Findings by severity (Critical/High/Medium/Low)
- Per-host detailed results
- Recommendations based on findings

#### JSON Report (scan_results.json)
- Structured data for integration
- Complete scan metadata
- All findings in parseable format

## 🏗️ Scanning Workflow

### Internal Infrastructure Scanning
```
1. Host Discovery
   └── Multi-method discovery (SYN, ACK, UDP pings)

2. AD Service Discovery
   └── Ports: 88,135,139,389,445,464,636,3268,3269

3. SMB Enumeration (if enabled)
   └── Scripts: smb-enum-*, smb-vuln-*, smb-os-discovery

4. LDAP/Kerberos Analysis
   └── Scripts: ldap-*, krb5-enum-users

5. Additional Services
   └── MS-RPC, NetBIOS, WinRM, MSSQL, Exchange
```

### External Infrastructure Scanning
```
1. Conservative Host Discovery
   └── Top 20 ports with retries

2. Service Identification
   └── Version detection on discovered services

3. Targeted Assessments (based on options)
   ├── SSL/TLS Security
   ├── Web Application Testing
   ├── SMB Vulnerabilities
   └── General Vulnerability Scanning

4. Timing Controls
   └── Delays between hosts (slow mode)
   └── Scan delays between probes
```

## ⚡ Performance Considerations

### Scan Duration Estimates

| Scan Type | Timing | Single Host | /24 Network |
|-----------|--------|-------------|-------------|
| Top Ports | Aggressive | ~2 min | ~30 min |
| Top Ports | Normal | ~5 min | ~1 hour |
| Top Ports | Slow | ~15 min | ~3 hours |
| Full Scan | Aggressive | ~20 min | ~3 hours |
| Full Scan | Normal | ~40 min | ~6 hours |
| Full Scan | Slow | ~2 hours | ~12+ hours |

### Optimization Tips

1. **Start with top ports**: Use `--top-ports` for initial assessment
2. **Skip discovery if needed**: Use `--skip-discovery` for known live hosts
3. **Use aggressive timing internally**: Safe for internal networks
4. **Combine related scans**: `--ssl-scan --web-scan` for web servers
5. **Custom ports for targeted scanning**: Use `--ports` for specific services



## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Test thoroughly before submitting
2. Document new features
3. Follow existing code style
4. Update README for new functionality


## ⚠️ Disclaimer

This tool is provided for legitimate security testing and network administration purposes only. Users are solely responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

**Use responsibly and ethically.**

## 🙏 Acknowledgments

- **Nmap Project** - For the powerful scanning engine
- **Python Community** - For excellent standard libraries
- **Security Community** - For continuous feedback and improvements

---

**Made with ❤️ for the security community**

*For questions or support, please open an issue on the project repository.*
