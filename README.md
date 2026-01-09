```markdown
# 🔍 IP Digger v2.0

**Advanced IP Intelligence & OSINT Gathering Tool**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/demonala/IP-DIGGER)
[![Telegram](https://img.shields.io/badge/Telegram-MolimnoCommunity-blue)](https://t.me/MolimnoChannel)

A comprehensive IP address intelligence tool that extracts maximum information from any IP address for authorized security research and network analysis.

## ⚡ Features

### 📊 **IP Intelligence**
- **Geolocation**: Country, region, city, coordinates
- **ISP Information**: Internet Service Provider details
- **Network Data**: WHOIS information, netname, organization
- **Reverse DNS**: Hostname lookup and resolution

### 🔍 **Network Scanning**
- **Port Scanning**: Common ports (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080)
- **Service Detection**: Identify running services
- **Ping Testing**: Check host availability and response time

### 🛡️ **Threat Intelligence**
- **Threat Checking**: Basic threat database lookups
- **VPN/Proxy Detection**: Identify anonymization services
- **Blacklist Monitoring**: DNS-based blacklist checking

### 📈 **Advanced Features**
- **Batch Processing**: Scan multiple IPs from file
- **Results Export**: Save findings to text files
- **Interactive CLI**: User-friendly command interface
- **Multi-Source Verification**: Cross-reference data from multiple APIs

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/demonala/IP-DIGGER.git
cd IP-DIGGER

# Install dependencies
pip install requests
```

Basic Usage

```bash
# Scan a single IP address
python ip_digger.py 8.8.8.8

# Scan a domain/hostname
python ip_digger.py google.com

# Launch interactive mode
python ip_digger.py
```

📖 Usage Examples

Example 1: Single IP Scan

```bash
python ip_digger.py 192.168.1.1
```

Sample Output:

```
IP DIGGER REPORT - 8.8.8.8
============================================================

[📌 BASIC INFORMATION]
  IP Address: 8.8.8.8
  IP Type: Public
  Reverse DNS: dns.google
  Ping Status: Alive (12ms)

[🔌 OPEN PORTS]
  53 (DNS), 443 (HTTPS)

[🌍 GEOLOCATION]
  Country: United States
  Region: California
  City: Mountain View
  ISP: Google LLC
  Coordinates: 37.4056, -122.0775
  Google Maps: https://maps.google.com/?q=37.4056,-122.0775

[📄 WHOIS INFORMATION]
  netname: GOOGLE
  country: US
  descr: Google LLC
```

Example 2: Interactive Mode

```bash
python ip_digger.py

1. Scan Single IP
2. Scan Hostname
3. Scan Local Network Info
4. Batch Scan (from file)
5. Exit
```

Example 3: Batch Scanning

```bash
# Create file with IPs
echo "8.8.8.8" > ips.txt
echo "1.1.1.1" >> ips.txt

# Run batch scan
python ip_digger.py
# Select option 4 and provide filename
```

🎯 Use Cases

🔒 For Security Professionals

· Penetration Testing: Reconnaissance phase
· Threat Hunting: Identify suspicious IPs
· Incident Response: Investigate malicious IPs

🏢 For Network Administrators

· Network Mapping: Discover devices on network
· Service Monitoring: Check open ports
· Geolocation: Understand traffic origins

🎓 For Researchers & Students

· OSINT Research: Open source intelligence gathering
· Academic Projects: Network security studies
· CTF Challenges: Capture The Flag competitions

⚙️ Configuration

Edit the configuration section in ip_digger.py:

```python
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10  # Request timeout in seconds
MAX_WORKERS = 5  # Concurrent threads for port scanning
```

📊 Output Formats

Screen Output

Colorful, organized display with emojis for easy reading

File Output

Results saved as timestamped text files:

```
ip_digger_8_8_8_8_20240105_143022.txt
```

Export Options

· Automatic: Prompt after each scan
· Manual: Use save function in interactive mode
· Batch: Combined results for multiple IPs

🛡️ Legal & Ethical Usage

STRICTLY FOR:

· ✅ Authorized security testing
· ✅ Educational purposes
· ✅ Personal network analysis
· ✅ Research with permission

PROHIBITED:

· ❌ Unauthorized network scanning
· ❌ Illegal surveillance
· ❌ Harassment or stalking
· ❌ Any criminal activity

Disclaimer

```
The developers assume no liability for misuse of this tool.
Users are solely responsible for complying with all applicable laws.
Always obtain proper authorization before scanning networks.
```

🐛 Troubleshooting

Common Issues

"Connection timed out"

· Check internet connection
· Verify firewall isn't blocking requests
· Try increasing timeout in configuration

"Port scan not working"

· Ensure you have proper permissions
· Check if target firewall is blocking
· Verify target is online

🔄 Updates & Roadmap

Planned Features

· Shodan integration (with API key)
· VirusTotal IP reporting
· Historical IP data
· Graphical user interface (GUI)
· Export to JSON/CSV formats

Version History

· v2.0 (Current): Multi-source intelligence, batch scanning
· v1.0: Basic geolocation and port scanning

🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

🌐 Community

Join Us

· Telegram: @MolimnoCommunity
· GitHub: demonala/IP-DIGGER

Support

· Create an Issue for bugs
· Use Telegram group for questions

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

```
MIT License

Copyright (c) 2024 Molimno Community

Permission is hereby granted...
```

🙏 Acknowledgments

· IP-API.com for free geolocation service
· ipapi.co for backup geolocation data
· RIPE NCC for WHOIS database access
· Python community for excellent libraries

⭐ Show Your Support

If you find this tool useful, please:

· ⭐ Star the repository
· 🐛 Report issues
· 💡 Suggest features
· 🔄 Share with others
· 💬 Join our community

---

Remember: With great power comes great responsibility. Use this tool ethically and legally.

Happy Researching! 🕵️‍♂️

---

Last Updated: January 2024
Maintained by Molimno Community

```

