#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP DIGGER v2.0
Cari informasi detail dari IP address
Created: 2023-10-15
Last Modified: 2024-01-05
Author: Local Researcher
"""

import socket
import requests
import json
import ipaddress
import time
import sys
import os
from datetime import datetime
import subprocess
import re
import concurrent.futures

# ===== CONFIG =====
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10
MAX_WORKERS = 5

# ===== UTILITIES =====
def is_valid_ip(ip_str):
    """Cek apakah string valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_local_ip():
    """Dapetin IP lokal"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def resolve_hostname(hostname):
    """Resolve hostname ke IP"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

# ===== IP LOOKUP SERVICES =====
class IPScanner:
    def __init__(self, ip_address):
        self.ip = ip_address
        self.results = {}
        self.start_time = time.time()
        
    def check_ip_type(self):
        """Cek jenis IP (public/private)"""
        try:
            ip = ipaddress.ip_address(self.ip)
            if ip.is_private:
                return "Private"
            elif ip.is_global:
                return "Public"
            elif ip.is_reserved:
                return "Reserved"
            elif ip.is_multicast:
                return "Multicast"
            else:
                return "Unknown"
        except:
            return "Invalid"
    
    def reverse_dns(self):
        """Reverse DNS lookup"""
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(self.ip)
            return hostname
        except:
            return "No reverse DNS"
    
    def ping_check(self):
        """Cek apakah IP aktif"""
        try:
            param = '-n' if sys.platform.lower() == 'win32' else '-c'
            command = ['ping', param, '2', '-W', '1', self.ip]
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            if "ttl=" in result.stdout.lower() or "time=" in result.stdout.lower():
                # Parse response time
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'time=' in line.lower():
                        time_match = re.search(r'time[=<](\d+(?:\.\d+)?)', line.lower())
                        if time_match:
                            return f"Alive ({time_match.group(1)}ms)"
                return "Alive"
            else:
                return "No response"
        except:
            return "Ping failed"
    
    def port_scan_common(self):
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080]
        open_ports = []
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            return port if result == 0 else None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in common_ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports[:10]  # Limit to 10 ports
    
    def geoip_lookup(self):
        """Lookup geolocation dari multiple sources"""
        geo_data = {}
        
        # Free IP API services (no API key needed)
        services = [
            {
                'name': 'ip-api.com',
                'url': f'http://ip-api.com/json/{self.ip}',
                'field_map': {
                    'country': 'country',
                    'region': 'regionName',
                    'city': 'city',
                    'isp': 'isp',
                    'org': 'org',
                    'as': 'as',
                    'lat': 'lat',
                    'lon': 'lon',
                    'timezone': 'timezone'
                }
            },
            {
                'name': 'ipapi.co',
                'url': f'https://ipapi.co/{self.ip}/json/',
                'field_map': {
                    'country': 'country_name',
                    'region': 'region',
                    'city': 'city',
                    'isp': 'org',
                    'lat': 'latitude',
                    'lon': 'longitude',
                    'timezone': 'timezone'
                }
            }
        ]
        
        headers = {'User-Agent': USER_AGENT}
        
        for service in services:
            try:
                response = requests.get(service['url'], headers=headers, timeout=TIMEOUT)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Map fields
                    for key, source_key in service['field_map'].items():
                        if source_key in data and data[source_key]:
                            geo_data[f"{service['name']}_{key}"] = data[source_key]
                    
                    # If we got good data from first service, break
                    if 'country' in str(geo_data) and geo_data.get(f"{service['name']}_country"):
                        geo_data['primary_source'] = service['name']
                        break
                        
            except Exception as e:
                continue
        
        return geo_data
    
    def whois_lookup(self):
        """Basic WHOIS lookup"""
        try:
            # For Linux/Unix
            if sys.platform in ['linux', 'darwin']:
                result = subprocess.run(['whois', self.ip], capture_output=True, text=True)
                output = result.stdout
                
                # Parse important fields
                whois_info = {}
                
                patterns = {
                    'netname': r'netname:\s*(.+)',
                    'country': r'country:\s*(.+)',
                    'descr': r'descr:\s*(.+)',
                    'org-name': r'org-name:\s*(.+)',
                    'inetnum': r'inetnum:\s*(.+)',
                    'created': r'created:\s*(.+)',
                    'last-modified': r'last-modified:\s*(.+)'
                }
                
                for key, pattern in patterns.items():
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        whois_info[key] = match.group(1).strip()
                
                return whois_info if whois_info else {"raw": output[:500]}
            
            # For Windows or fallback
            else:
                # Use RIPE whois API
                url = f"https://rest.db.ripe.net/search.json?query-string={self.ip}"
                response = requests.get(url, timeout=TIMEOUT)
                
                if response.status_code == 200:
                    data = response.json()
                    whois_info = {}
                    
                    # Parse RIPE response
                    if 'objects' in data and 'object' in data['objects']:
                        for obj in data['objects']['object']:
                            if 'attributes' in obj:
                                for attr in obj['attributes']['attribute']:
                                    if attr.get('name') in ['netname', 'country', 'descr']:
                                        whois_info[attr['name']] = attr.get('value', '')
                    
                    return whois_info
                
        except Exception as e:
            return {"error": str(e)}
        
        return {"info": "WHOIS not available"}
    
    def shodan_check(self):
        """Check if IP has Shodan data (no API key)"""
        # Note: Shodan requires API key for full access
        # This just checks if it might be in Shodan
        try:
            # Quick check via HTTP headers
            test_urls = [
                f"http://{self.ip}",
                f"https://{self.ip}"
            ]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code < 400:
                        return {
                            "http_service": "Detected",
                            "server": response.headers.get('Server', 'Unknown'),
                            "title": self.extract_title(response.text)
                        }
                except:
                    continue
            
            # Check common ports
            common_ports = [80, 443, 22, 21, 23]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.ip, port))
                    if result == 0:
                        return {"open_ports": common_ports}
                    sock.close()
                except:
                    pass
            
        except Exception as e:
            return {"note": "Limited scan without API keys"}
        
        return {"info": "No obvious services detected"}
    
    def extract_title(self, html):
        """Extract title from HTML"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()[:100]
        return "No title"
    
    def threat_intel_check(self):
        """Check IP against known threat databases"""
        # Free threat intelligence sources
        threat_checks = {}
        
        # AbuseIPDB public API (limited)
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': '',  # Would need API key for full access
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': self.ip,
                'maxAgeInDays': 90
            }
            
            # Without API key, we can't access this
            # This is just the structure
            threat_checks['abuseipdb'] = "API key required for full check"
            
        except:
            threat_checks['abuseipdb'] = "Check failed"
        
        # Manual check of known bad IP ranges
        bad_ranges = [
            "185.159.128.0/24",  # Example malicious range
            "192.168.0.0/16",    # Private, not necessarily bad
        ]
        
        ip_obj = ipaddress.ip_address(self.ip)
        for range_str in bad_ranges:
            network = ipaddress.ip_network(range_str)
            if ip_obj in network:
                threat_checks['known_bad_range'] = range_str
        
        # Check if it's a VPN/proxy (basic check)
        vpn_asns = ['AS60068', 'AS196658', 'AS14061']  # Example VPN ASNs
        if 'ip-api.com_as' in self.results.get('geoip', {}):
            asn = self.results['geoip'].get('ip-api.com_as', '')
            for vpn_asn in vpn_asns:
                if vpn_asn in asn:
                    threat_checks['vpn_proxy'] = asn
        
        return threat_checks if threat_checks else {"status": "No known threats detected"}
    
    def get_ip_history(self):
        """Get historical IP information (if available)"""
        # Limited without paid APIs
        history_info = {}
        
        # Check if IP has changed recently via DNS
        try:
            # This would require historical DNS data
            # For now, just note the possibility
            history_info['note'] = "Historical data requires paid APIs"
            
            # Check if IP is in any blacklists (via DNSBL)
            dnsbl_servers = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'dnsbl.sorbs.net'
            ]
            
            reversed_ip = '.'.join(reversed(self.ip.split('.')))
            
            for dnsbl in dnsbl_servers:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    socket.gethostbyname(query)
                    history_info['blacklisted'] = dnsbl
                except:
                    pass
                    
        except Exception as e:
            history_info['error'] = str(e)
        
        return history_info
    
    def run_full_scan(self):
        """Run semua scan methods"""
        print(f"\n[+] Starting scan for IP: {self.ip}")
        print(f"[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        # Run all checks
        checks = [
            ("IP Type", self.check_ip_type),
            ("Reverse DNS", self.reverse_dns),
            ("Ping", self.ping_check),
            ("Common Ports", self.port_scan_common),
            ("Geolocation", self.geoip_lookup),
            ("WHOIS", self.whois_lookup),
            ("Services", self.shodan_check),
            ("Threat Intel", self.threat_intel_check),
            ("History", self.get_ip_history)
        ]
        
        results = {}
        
        for check_name, check_func in checks:
            print(f"[*] Running {check_name}...")
            try:
                result = check_func()
                results[check_name.lower().replace(" ", "_")] = result
                
                # Display immediately for some checks
                if check_name in ["IP Type", "Reverse DNS", "Ping"]:
                    print(f"    → {result}")
                    
            except Exception as e:
                results[check_name.lower().replace(" ", "_")] = {"error": str(e)}
                print(f"    → Error: {str(e)[:50]}")
            
            time.sleep(0.5)  # Be polite to APIs
        
        self.results = results
        
        # Calculate scan time
        scan_time = time.time() - self.start_time
        self.results['scan_time'] = f"{scan_time:.2f} seconds"
        
        return self.results
    
    def display_results(self):
        """Display results in readable format"""
        if not self.results:
            print("[-] No results to display")
            return
        
        print(f"\n{'='*60}")
        print(f"IP DIGGER REPORT - {self.ip}")
        print(f"Scan completed in {self.results.get('scan_time', 'N/A')}")
        print(f"{'='*60}\n")
        
        # Basic Info
        print("[📌 BASIC INFORMATION]")
        print(f"  IP Address: {self.ip}")
        print(f"  IP Type: {self.results.get('ip_type', 'N/A')}")
        print(f"  Reverse DNS: {self.results.get('reverse_dns', 'N/A')}")
        print(f"  Ping Status: {self.results.get('ping', 'N/A')}")
        
        # Ports
        if 'common_ports' in self.results and self.results['common_ports']:
            print(f"\n[🔌 OPEN PORTS]")
            ports = self.results['common_ports']
            port_list = ', '.join(str(p) for p in ports)
            print(f"  {port_list}")
            
            # Show common services
            port_services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MS RPC',
                139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
                993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
                3389: 'RDP', 5900: 'VNC', 8080: 'HTTP Proxy'
            }
            
            for port in ports:
                if port in port_services:
                    print(f"    Port {port}: {port_services[port]}")
        
        # Geolocation
        if 'geolocation' in self.results:
            geo = self.results['geolocation']
            print(f"\n[🌍 GEOLOCATION]")
            
            # Try to get from ip-api first
            for source in ['ip-api.com', 'ipapi.co']:
                country_key = f"{source}_country"
                if country_key in geo:
                    print(f"  Country: {geo.get(country_key, 'N/A')}")
                    print(f"  Region: {geo.get(f'{source}_region', 'N/A')}")
                    print(f"  City: {geo.get(f'{source}_city', 'N/A')}")
                    print(f"  ISP: {geo.get(f'{source}_isp', 'N/A')}")
                    print(f"  Organization: {geo.get(f'{source}_org', 'N/A')}")
                    
                    if f'{source}_lat' in geo and f'{source}_lon' in geo:
                        lat = geo[f'{source}_lat']
                        lon = geo[f'{source}_lon']
                        print(f"  Coordinates: {lat}, {lon}")
                        print(f"  Google Maps: https://maps.google.com/?q={lat},{lon}")
                    
                    break
        
        # WHOIS
        if 'whois' in self.results:
            whois = self.results['whois']
            if isinstance(whois, dict) and len(whois) > 0:
                print(f"\n[📄 WHOIS INFORMATION]")
                for key, value in whois.items():
                    if key != 'raw' and value:
                        print(f"  {key}: {value}")
        
        # Services
        if 'services' in self.results:
            services = self.results['services']
            if isinstance(services, dict) and len(services) > 0:
                print(f"\n[🛠️ DETECTED SERVICES]")
                for key, value in services.items():
                    print(f"  {key}: {value}")
        
        # Threat Intel
        if 'threat_intel' in self.results:
            threats = self.results['threat_intel']
            if isinstance(threats, dict) and len(threats) > 0:
                print(f"\n[⚠️ THREAT INTELLIGENCE]")
                for key, value in threats.items():
                    if value and "required" not in str(value).lower():
                        print(f"  {key}: {value}")
        
        # History
        if 'history' in self.results:
            history = self.results['history']
            if isinstance(history, dict) and len(history) > 0:
                print(f"\n[📜 HISTORICAL DATA]")
                for key, value in history.items():
                    print(f"  {key}: {value}")
        
        print(f"\n{'='*60}")
        print("[+] Scan completed")
        
        # Save option
        save = input("\n[?] Save results to file? (y/n): ").strip().lower()
        if save == 'y':
            self.save_results()
    
    def save_results(self):
        """Save results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ip_digger_{self.ip.replace('.', '_')}_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"IP DIGGER REPORT\n")
                f.write(f"="*50 + "\n")
                f.write(f"Target IP: {self.ip}\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan Time: {self.results.get('scan_time', 'N/A')}\n")
                f.write(f"="*50 + "\n\n")
                
                for section, data in self.results.items():
                    if section != 'scan_time':
                        f.write(f"[{section.upper().replace('_', ' ')}]\n")
                        if isinstance(data, dict):
                            for key, value in data.items():
                                f.write(f"  {key}: {value}\n")
                        elif isinstance(data, list):
                            f.write(f"  {', '.join(str(x) for x in data)}\n")
                        else:
                            f.write(f"  {data}\n")
                        f.write("\n")
            
            print(f"[+] Results saved to: {filename}")
            return filename
        except Exception as e:
            print(f"[-] Failed to save: {e}")
            return None

# ===== MAIN INTERFACE =====
def banner():
    print(r"""
     ___ ____   ____ _   _ _____ 
    |_ _|  _ \ / ___| | | | ____|
     | || |_) | |  _| |_| |  _|  
     | ||  __/| |_| |  _  | |___ 
    |___|_|    \____|_| |_|_____|
    
        IP Intelligence Digger
           v2.0 | @MolimnoCommunity
    """)

def main():
    """Main function"""
    banner()
    
    print("[!] For educational and authorized research only")
    print("[!] Use responsibly and legally\n")
    
    while True:
        print("\n" + "="*60)
        print("1. Scan Single IP")
        print("2. Scan Hostname")
        print("3. Scan Local Network Info")
        print("4. Batch Scan (from file)")
        print("5. Exit")
        print("="*60)
        
        try:
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                ip = input("\nEnter IP address: ").strip()
                
                if not is_valid_ip(ip):
                    print("[-] Invalid IP address")
                    continue
                
                scanner = IPScanner(ip)
                scanner.run_full_scan()
                scanner.display_results()
                
            elif choice == "2":
                hostname = input("\nEnter hostname/domain: ").strip()
                
                print("[*] Resolving hostname...")
                ip = resolve_hostname(hostname)
                
                if not ip:
                    print("[-] Could not resolve hostname")
                    continue
                
                print(f"[+] Resolved to IP: {ip}")
                
                scanner = IPScanner(ip)
                scanner.run_full_scan()
                scanner.display_results()
                
            elif choice == "3":
                print("\n[🖥️ LOCAL SYSTEM INFORMATION]")
                local_ip = get_local_ip()
                print(f"  Local IP: {local_ip}")
                
                # Get public IP
                try:
                    response = requests.get("https://api.ipify.org", timeout=5)
                    if response.status_code == 200:
                        print(f"  Public IP: {response.text}")
                        
                        # Quick scan of public IP
                        scan = input("\n[?] Quick scan of public IP? (y/n): ").strip().lower()
                        if scan == 'y':
                            scanner = IPScanner(response.text)
                            scanner.run_full_scan()
                            scanner.display_results()
                except:
                    print("  Public IP: Could not determine")
                
                # Network interfaces (Linux/Unix)
                if sys.platform in ['linux', 'darwin']:
                    try:
                        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                        if result.returncode == 0:
                            print("\n[📡 NETWORK INTERFACES]")
                            lines = result.stdout.split('\n')
                            for line in lines:
                                if 'inet ' in line and '127.0.0.1' not in line:
                                    print(f"  {line.strip()}")
                    except:
                        pass
                
            elif choice == "4":
                filename = input("\nEnter filename with IPs (one per line): ").strip()
                
                if not os.path.exists(filename):
                    print("[-] File not found")
                    continue
                
                try:
                    with open(filename, 'r') as f:
                        ips = [line.strip() for line in f if line.strip()]
                    
                    valid_ips = []
                    for ip in ips:
                        if is_valid_ip(ip):
                            valid_ips.append(ip)
                        else:
                            # Try to resolve as hostname
                            resolved = resolve_hostname(ip)
                            if resolved:
                                valid_ips.append(resolved)
                    
                    if not valid_ips:
                        print("[-] No valid IPs found")
                        continue
                    
                    print(f"[+] Found {len(valid_ips)} valid IPs to scan")
                    
                    output_file = f"batch_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    
                    with open(output_file, 'w') as out_f:
                        out_f.write("BATCH IP SCAN RESULTS\n")
                        out_f.write("="*50 + "\n\n")
                        
                        for i, ip in enumerate(valid_ips, 1):
                            print(f"\n[{i}/{len(valid_ips)}] Scanning {ip}")
                            
                            scanner = IPScanner(ip)
                            results = scanner.run_full_scan()
                            
                            # Write to file
                            out_f.write(f"IP: {ip}\n")
                            if 'geolocation' in results:
                                geo = results['geolocation']
                                country = next((geo[k] for k in geo if 'country' in k), 'N/A')
                                isp = next((geo[k] for k in geo if 'isp' in k), 'N/A')
                                out_f.write(f"  Country: {country}, ISP: {isp}\n")
                            out_f.write(f"  Status: {results.get('ping', 'N/A')}\n")
                            out_f.write(f"  Open Ports: {results.get('common_ports', [])}\n")
                            out_f.write("-"*30 + "\n")
                            
                            time.sleep(2)  # Rate limiting
                    
                    print(f"\n[+] Batch scan complete. Results in: {output_file}")
                    
                except Exception as e:
                    print(f"[-] Error: {e}")
                
            elif choice == "5":
                print("\n[+] Exiting IP Digger...")
                break
                
            else:
                print("[-] Invalid option")
        
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
            break
        except Exception as e:
            print(f"[-] Error: {e}")

# ===== COMMAND LINE INTERFACE =====
if __name__ == "__main__":
    # Check if IP provided as argument
    if len(sys.argv) > 1:
        ip_arg = sys.argv[1]
        
        if is_valid_ip(ip_arg):
            scanner = IPScanner(ip_arg)
            scanner.run_full_scan()
            scanner.display_results()
        else:
            # Try as hostname
            resolved = resolve_hostname(ip_arg)
            if resolved:
                scanner = IPScanner(resolved)
                scanner.run_full_scan()
                scanner.display_results()
            else:
                print(f"[-] Invalid IP or hostname: {ip_arg}")
                print("[*] Starting interactive mode...\n")
                time.sleep(2)
                main()
    else:
        main()
