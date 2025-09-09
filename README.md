# Enhanced Multi-Stage Network Scanner

A comprehensive Python-based network scanning tool that performs intelligent host discovery and multi-stage port scanning using Nmap. This tool is designed for penetration testers, security researchers, and network administrators who need thorough network reconnaissance.

<img width="1529" height="507" alt="image" src="https://github.com/user-attachments/assets/6debdcb5-debb-42e2-8fe2-2cba9f1f426b" />


## 🚀 Features

### Multi-Stage Scanning Architecture
- **Stage 1**: Host Discovery using `-Pn` with port scanning (bypasses ping blocks)
- **Stage 2**: Fast Scan on top 1000 ports with service detection
- **Stage 3**: Full Port Scan on all 65535 ports
- **Stage 4**: UDP Scan on common ports
- **Stage 5**: SNMP Configuration Check for misconfigurations

### Advanced Capabilities
- ✅ **Firewall-Resistant Discovery** - Uses `-Pn` flag to bypass ping blocks
- ✅ **Multi-threading** - Parallel execution for faster scanning
- ✅ **Flexible Stage Control** - Skip any stage based on your needs
- ✅ **Comprehensive Reporting** - Multiple output formats and summaries
- ✅ **Target Format Support** - Individual IPs, CIDR ranges, and IP ranges
- ✅ **Error Handling** - Robust timeout and error management
- ✅ **Progress Tracking** - Real-time colored status updates

## 📋 Requirements

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap snmp-utils python3

# CentOS/RHEL
sudo yum install nmap net-snmp-utils python3

# macOS (using Homebrew)
brew install nmap net-snmp
```

### Python Requirements
- Python 3.6+
- Standard library modules (no additional pip packages required)

## 🔧 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Amrkadry/EIPT-Scanner.git
cd enhanced-network-scanner
```

2. **Make executable:**
```bash
chmod +x enhanced_nmap.py
```

3. **Verify dependencies:**
```bash
nmap --version
snmpwalk -V
python3 --version
```

## 📖 Usage

### Basic Usage
```bash
python3 enhanced_nmap.py targets.txt
```

### Command Line Options

#### Individual Stage Control
```bash
--skip-ping     # Skip host discovery (assume all targets are live)
--skip-fast     # Skip fast scan (top 1000 ports)
--skip-full     # Skip full port scan (all 65535 ports)
--skip-udp      # Skip UDP scan
--skip-snmp     # Skip SNMP configuration check
```

#### Convenience Options
```bash
--fast-only     # Only run host discovery + fast scan
--tcp-only      # Only TCP scans (skip UDP and SNMP)
--udp-only      # Only host discovery + UDP/SNMP scans
```

### Target File Format

Create a `targets.txt` file with one target per line:

```
192.168.1.1
192.168.1.0/24
10.0.0.1-10
172.16.1.100
```

**Supported formats:**
- Individual IPs: `192.168.1.1`
- CIDR notation: `192.168.1.0/24`
- IP ranges: `192.168.1.1-10`
- Mixed combinations

## 💡 Usage Examples

### Quick Network Discovery
```bash
# Fast scan only (quickest option)
python3 enhanced_nmap.py targets.txt --fast-only
```

### Comprehensive TCP Scanning
```bash
# Skip time-consuming UDP scans
python3 enhanced_nmap.py targets.txt --tcp-only
```

### Thorough Network Assessment
```bash
# Skip only the slow full port scan
python3 enhanced_nmap.py targets.txt --skip-full
```

### Known Live Hosts
```bash
# Skip host discovery when targets don't respond to ping
python3 enhanced_nmap.py targets.txt --skip-ping
```

### UDP Service Discovery
```bash
# Focus on UDP services and SNMP
python3 enhanced_nmap.py targets.txt --udp-only
```

### Custom Combinations
```bash
# Multiple skip options
python3 enhanced_nmap.py targets.txt --skip-full --skip-udp --skip-snmp
```

## 📁 Output Files

The scanner creates a `nmap_results/` directory with the following files:

### Per-Host Results
- `{ip}-1000.txt` - Fast scan results (top 1000 ports)
- `{ip}-full.txt` - Full port scan results (all 65535 ports)
- `{ip}-udp.txt` - UDP scan results
- `{ip}-snmp.txt` - SNMP configuration check results

### Summary Reports
- `live_hosts.txt` - List of discovered live hosts
- `scan_summary.txt` - TCP scan summary for all hosts
- `udp_summary.txt` - UDP scan summary
- `snmp_summary.txt` - SNMP vulnerability summary

## 🏗️ Architecture

### Scanning Workflow

```
📡 Stage 1: Host Discovery
    ├── Uses: nmap -Pn -sS --top-ports 100
    ├── Purpose: Find live hosts that respond to port scans
    └── Output: live_hosts.txt

⚡ Stage 2: Fast Scan  
    ├── Uses: nmap -Pn -sCV -T4 --top-ports 1000
    ├── Purpose: Quick service discovery on common ports
    └── Output: {ip}-1000.txt

🔍 Stage 3: Full Port Scan
    ├── Uses: nmap -Pn -sCV -T4 -p-
    ├── Purpose: Comprehensive scan of all 65535 ports
    └── Output: {ip}-full.txt

📡 Stage 4: UDP Scan
    ├── Uses: nmap -Pn -sU -T4 -p{common_udp_ports}
    ├── Purpose: Discover UDP services
    └── Output: {ip}-udp.txt

🔒 Stage 5: SNMP Check
    ├── Uses: snmpwalk -v2c -c public
    ├── Purpose: Check for SNMP misconfigurations
    └── Output: {ip}-snmp.txt
```

### Threading Strategy
- **Host Discovery**: Single-threaded (network topology dependent)
- **Fast Scan**: Up to 10 concurrent threads
- **Full Scan**: Up to 5 concurrent threads (resource intensive)
- **UDP Scan**: Up to 3 concurrent threads (slower protocol)
- **SNMP Check**: Up to 10 concurrent threads

## ⚙️ Configuration

### Timeout Settings
```python
TIMEOUT_PING = 60      # Host discovery timeout
TIMEOUT_FAST = 300     # Fast scan timeout (5 minutes)
TIMEOUT_FULL = 1800    # Full scan timeout (30 minutes)
TIMEOUT_UDP = 900      # UDP scan timeout (15 minutes)
```

### Thread Limits
```python
MAX_THREADS = 10       # Maximum concurrent threads
```

### UDP Ports Scanned
```
53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353
```

## 🛡️ Security Considerations

### Legal Usage
- **Only scan networks you own or have explicit permission to test**
- Unauthorized network scanning may violate laws and policies
- Always follow responsible disclosure practices

### Network Impact
- The tool uses aggressive timing (`-T4`) for faster results
- Full port scans can generate significant network traffic
- Consider using `--fast-only` for initial reconnaissance

### Stealth Considerations
- Uses SYN scanning (`-sS`) which is more stealthy than connect scans
- Multiple threads may increase detection probability
- Consider reducing thread count for stealth operations

## 🐛 Troubleshooting

### Common Issues

#### "No live hosts found"
```bash
# Try skipping host discovery
python3 enhanced_nmap.py targets.txt --skip-ping

# Or use fast-only mode
python3 enhanced_nmap.py targets.txt --fast-only
```

#### Permission errors
```bash
# Run with sudo for raw socket access
sudo python3 enhanced_nmap.py targets.txt
```

#### Missing dependencies
```bash
# Install missing tools
sudo apt install nmap snmp-utils  # Ubuntu/Debian
sudo yum install nmap net-snmp-utils  # CentOS/RHEL
```

#### SNMP check fails
```bash
# Skip SNMP if snmpwalk is not available
python3 enhanced_nmap.py targets.txt --skip-snmp
```

### Debug Mode
Add debug output by modifying the `print_status` function calls or using verbose nmap options.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 Python style guidelines
- Add docstrings to new functions
- Test with various target formats
- Update README for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for legitimate security testing and network administration purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this software.

## 🙏 Acknowledgments

- **Nmap Project** - For the powerful network scanning engine
- **Net-SNMP Project** - For SNMP utilities
- **Python Community** - For excellent threading and subprocess libraries

---

**Made with ❤️ for the cybersecurity community**
