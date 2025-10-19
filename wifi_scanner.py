# wifi_scanner.py
import subprocess
import re
from collections import defaultdict
import time
from datetime import datetime

class WiFiScanner:
    def __init__(self):
        self.trusted_enterprise_prefixes = ['CORP_', 'OFFICE_', 'ENTERPRISE_', 'COMPANY_']
        self.malicious_keywords = ['free', 'public', 'guest', 'hotspot', 'admin', 'setup']
        self.legitimate_brands = ['starbucks', 'att', 'verizon', 'xfinity', 'tmobile', 'google']
        
        self.suspicious_patterns = [
            r'^[0-9]{10,}$',                    # Long numeric SSIDs
            r'^[A-Z]{15,}$',                    # Long uppercase strings
            r'.*@.*',                           # Contains @ symbol
            r'.*_.*_.*_.*',                     # Multiple underscores
            r'^DIRECT-[a-zA-Z0-9]{4}',          # Windows direct connection
            r'^AndroidAP_[0-9a-fA-F]{6}$',      # Generic Android hotspot
        ]
        
        # Known manufacturer OUI prefixes (first 3 bytes of MAC)
        self.trusted_manufacturers = [
            'Cisco', 'Aruba', 'Ruckus', 'Ubiquiti', 'Meraki', 
            'Netgear', 'TP-Link', 'D-Link', 'Linksys'
        ]
        

    def parse_netsh_output(self, output):
        """Parse netsh command output with improved security detection"""
        networks = []
        current_ssid = None
        networks_dict = {}
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('SSID') and 'BSSID' not in line:
                ssid_match = re.match(r'SSID\s*\d+\s*:\s*(.+)', line)
                if ssid_match:
                    current_ssid = ssid_match.group(1).strip()
                    if current_ssid not in networks_dict:
                        networks_dict[current_ssid] = {'bssids': [], 'security': 'UNKNOWN'}
            
            elif line.startswith('BSSID') and current_ssid:
                bssid_match = re.search(r'BSSID\s*\d+\s*:\s*([0-9a-fA-F:]{17})', line)
                if bssid_match:
                    current_bssid = bssid_match.group(1).upper()
                    networks_dict[current_ssid]['bssids'].append({
                        'mac': current_bssid,
                        'signal': -100,
                        'signal_percent': 0,
                        'channel': 0,
                    })
            
            elif 'Signal' in line and current_ssid and networks_dict[current_ssid]['bssids']:
                signal_match = re.search(r'Signal\s*:\s*(\d+)%', line, re.IGNORECASE)
                if signal_match:
                    signal_percent = int(signal_match.group(1))
                    networks_dict[current_ssid]['bssids'][-1]['signal'] = self.convert_signal_to_dbm(signal_percent)
                    networks_dict[current_ssid]['bssids'][-1]['signal_percent'] = signal_percent
            
            # Channel line
            elif 'Channel' in line and current_ssid and networks_dict[current_ssid]['bssids']:
                channel_match = re.search(r'Channel\s*:\s*(\d+)', line, re.IGNORECASE)
                if channel_match:
                    networks_dict[current_ssid]['bssids'][-1]['channel'] = int(channel_match.group(1))
            
            # Authentication line - FIXED
            elif 'Authentication' in line and current_ssid:
                auth_match = re.search(r'Authentication\s*:\s*(.+)', line, re.IGNORECASE)
                if auth_match:
                    auth_type = auth_match.group(1).strip()
                    networks_dict[current_ssid]['security'] = self.classify_security(auth_type)
        
        # Convert dictionary to list format
        for ssid, data in networks_dict.items():
            for bssid in data['bssids']:
                networks.append({
                    'ssid': ssid,
                    'bssid_mac': bssid['mac'],
                    'security': data['security'],  # Use the SSID-level security
                    'signal_strength': bssid['signal'],
                    'signal_percent': bssid.get('signal_percent', 0),
                    'channel': bssid['channel']
                })
        
        return networks

    def classify_security(self, auth_type):
        """Improved security classification"""
        if not auth_type:
            return 'UNKNOWN'
            
        auth_lower = auth_type.lower()
        
        # WPA3
        if 'wpa3' in auth_lower:
            return 'WPA3'
        
        # Enterprise
        elif any(x in auth_lower for x in ['enterprise', '802.1x']):
            return 'WPA2-ENTERPRISE'
        
        # WPA2
        elif any(x in auth_lower for x in ['wpa2', 'wpa2-personal']):
            return 'WPA2'
        
        # WPA
        elif 'wpa' in auth_lower:
            return 'WPA'
        
        # WEP
        elif 'wep' in auth_lower:
            return 'WEP'
        
        # Open network
        elif any(x in auth_lower for x in ['open', 'none']):
            return 'OPEN'
        
        else:
            return 'UNKNOWN'
        
    def convert_signal_to_dbm(self, signal_percent):
        """Convert signal percentage to dBm accurately"""
        # More accurate conversion: 100% = -20 dBm, 0% = -100 dBm
        return int(-20 - ((100 - signal_percent) * 0.8))

    def analyze_manufacturer_risk(self, mac_address):
        """Analyze MAC address manufacturer for risk assessment"""
        # Extract OUI (first 3 bytes)
        oui = mac_address.replace(':', '')[:6].upper()
        
        common_router_ouis = ['000C43', '001DE1', '0022B0', '14CC20', '1C3BF3']
        mobile_ouis = ['A0F849', '885395', 'F0272D']
        
        if oui in common_router_ouis:
            return -10, "Known router manufacturer"
        elif oui in mobile_ouis:
            return 15, "Mobile device hotspot"
        else:
            return 0, "Unknown manufacturer"

    def analyze_signal_risk(self, network, all_networks):
        """Advanced signal analysis for evil twin detection"""
        risk_score = 0
        reasons = []
        
        ssid = network['ssid']
        current_bssid = network.get('bssid_mac', '')
        current_signal = network.get('signal_strength', -100)
        
        # Find all networks with same SSID
        same_ssid_networks = [
            n for n in all_networks 
            if n['ssid'] == ssid and n.get('bssid_mac') != current_bssid
        ]
        
        if same_ssid_networks:
            # Compare signal strengths among duplicates
            strongest_signal = max(
                [n.get('signal_strength', -100) for n in same_ssid_networks] + [current_signal]
            )
            weakest_signal = min(
                [n.get('signal_strength', -100) for n in same_ssid_networks] + [current_signal]
            )
            
            # If this is the strongest among duplicates
            if current_signal == strongest_signal:
                signal_difference = strongest_signal - weakest_signal
                if signal_difference > 15:  # Significant signal advantage
                    risk_score += 25
                    reasons.append(f"Strongest signal among {len(same_ssid_networks)+1} duplicates (+{signal_difference}dB advantage)")
                else:
                    risk_score += 15
                    reasons.append(f"Strongest signal among {len(same_ssid_networks)+1} duplicates")
            
            # Check for signal strength inconsistencies
            if current_signal > -50 and len(same_ssid_networks) > 0:
                risk_score += 10
                reasons.append("Very strong signal with duplicate SSIDs")
        
        # Extremely strong signal analysis
        if current_signal > -30:
            risk_score += 20
            reasons.append("Extremely strong signal - possible high-power transmitter")
        elif current_signal > -40:
            risk_score += 10
            reasons.append("Very strong signal - monitor for consistency")
        
        return risk_score, reasons

    def analyze_ssid_pattern(self, ssid):
        """Enhanced SSID pattern analysis"""
        risk_score = 0
        reasons = []
        ssid_lower = ssid.lower()
        
        # Check for malicious keywords
        for keyword in self.malicious_keywords:
            if keyword in ssid_lower:
                risk_score += 15
                reasons.append(f"Contains suspicious keyword: '{keyword}'")
        
        # Check for legitimate brands (lower risk)
        is_legitimate_brand = any(brand in ssid_lower for brand in self.legitimate_brands)
        
        # Check suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, ssid):
                risk_score += 20
                reasons.append("Suspicious SSID pattern detected")
                break
        
        # Length analysis
        if len(ssid) > 30:
            risk_score += 15
            reasons.append("Unusually long SSID (>30 chars)")
        elif len(ssid) < 2:
            risk_score += 20
            reasons.append("Invalid SSID length (<2 chars)")
        
        # Character diversity analysis
        if len(ssid) > 8:
            unique_chars = len(set(ssid.lower()))
            diversity_ratio = unique_chars / len(ssid)
            if diversity_ratio < 0.3:
                risk_score += 15
                reasons.append("Low character diversity - possible automated generation")
        
        # Trusted enterprise networks (negative risk)
        if any(prefix in ssid for prefix in self.trusted_enterprise_prefixes):
            risk_score -= 20
            reasons.append("Trusted enterprise network prefix")
        
        return risk_score, reasons

    def analyze_security_risk(self, security_type, ssid):
        """Enhanced security risk analysis"""
        risk_score = 0
        reasons = []
        
        security_risks = {
            'OPEN': 40,
            'WEP': 35,
            'UNKNOWN': 25,
            'WPA': 10,
            'WPA2': 5,
            'WPA2-ENTERPRISE': -10,
            'WPA3': -15,
            'ENTERPRISE': -10
        }
        
        risk_points = security_risks.get(security_type, 20)
        risk_score += risk_points
        
        if risk_points > 0:
            reasons.append(f"{security_type} security: +{risk_points} risk")
        else:
            reasons.append(f"{security_type} security: {risk_points} risk (safe)")
        
        # Special case: Open network with legitimate-sounding name
        if security_type == 'OPEN' and any(brand in ssid.lower() for brand in self.legitimate_brands):
            risk_score += 10
            reasons.append("Open network impersonating legitimate brand")
        
        return risk_score, reasons

    def analyze_network_risk(self, network, all_networks):
        """Comprehensive network risk analysis"""
        ssid = network['ssid']
        risk_score = 0
        risk_reasons = []
        
        # 1. Security Analysis
        security_risk, security_reasons = self.analyze_security_risk(network['security'], ssid)
        risk_score += security_risk
        risk_reasons.extend(security_reasons)
        
        # 2. SSID Pattern Analysis
        ssid_risk, ssid_reasons = self.analyze_ssid_pattern(ssid)
        risk_score += ssid_risk
        risk_reasons.extend(ssid_reasons)
        
        # 3. Signal Analysis (Evil Twin Detection)
        signal_risk, signal_reasons = self.analyze_signal_risk(network, all_networks)
        risk_score += signal_risk
        risk_reasons.extend(signal_reasons)
        
        # 4. Manufacturer Analysis
        if network.get('bssid_mac'):
            manufacturer_risk, manufacturer_reason = self.analyze_manufacturer_risk(network['bssid_mac'])
            risk_score += manufacturer_risk
            if manufacturer_risk != 0:
                risk_reasons.append(manufacturer_reason)
        
        # 5. Channel Analysis
        channel = network.get('channel', 0)
        if channel in [1, 6, 11]:  # Standard non-overlapping channels
            risk_score -= 5
            risk_reasons.append("Standard channel usage")
        
        # Ensure risk score is within bounds
        risk_score = max(0, min(100, risk_score))
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "🔴 CRITICAL RISK"
        elif risk_score >= 50:
            risk_level = "🟠 HIGH RISK"
        elif risk_score >= 30:
            risk_level = "🟡 MEDIUM RISK"
        elif risk_score >= 15:
            risk_level = "🔵 LOW RISK"
        else:
            risk_level = "🟢 VERY LOW RISK"
        
        return {
            'ssid': ssid,
            'bssid': network.get('bssid_mac', 'Unknown'),
            'security': network.get('security', 'Unknown'),
            'signal_strength': network.get('signal_strength', -99),
            'signal_percent': network.get('signal_percent', 0),
            'channel': channel,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_reasons': risk_reasons,
            'duplicate_count': len([n for n in all_networks if n['ssid'] == ssid])
        }

    def scan_networks(self):
        """Perform comprehensive WiFi scan"""
        print("Scanning for WiFi networks...")
        
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                print("Failed to scan WiFi networks")
                return []
            
            # DEBUG: See what netsh is returning
            print("=== RAW NETSH OUTPUT ===")
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if any(keyword in line.lower() for keyword in ['ssid', 'authentication', 'encryption']):
                    print(f"{i:3d}: {line.strip()}")
            print("=== END DEBUG ===")
            
            # FIX: parse_netsh_output already returns flat list, no need to flatten again
            networks_for_analysis = self.parse_netsh_output(result.stdout)
            
            if not networks_for_analysis:
                print("No networks found")
                return []
            
            print(f"✅ Found {len(networks_for_analysis)} access points")
            
            # Print security types for debugging
            security_counts = {}
            for network in networks_for_analysis:
                sec = network['security']
                security_counts[sec] = security_counts.get(sec, 0) + 1
            
            print("Security type breakdown:", security_counts)
            
            # Analyze each network
            analyzed_networks = []
            for network in networks_for_analysis:
                analysis = self.analyze_network_risk(network, networks_for_analysis)
                analyzed_networks.append(analysis)
            
            # Sort by risk score (highest first)
            analyzed_networks.sort(key=lambda x: x['risk_score'], reverse=True)
            
            return analyzed_networks
            
        except subprocess.TimeoutExpired:
            print("WiFi scan timed out")
            return []
        except Exception as e:
            print(f"Error during WiFi scan: {e}")
            return []
    def generate_report(self, networks):
        """Generate comprehensive scan report"""
        if not networks:
            return "No networks found for analysis."
        
        report = []
        report.append("📡 WiFi Security Scan Report")
        report.append("=" * 50)
        report.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Risk statistics
        critical_risk = sum(1 for n in networks if n['risk_score'] >= 70)
        high_risk = sum(1 for n in networks if 50 <= n['risk_score'] < 70)
        medium_risk = sum(1 for n in networks if 30 <= n['risk_score'] < 50)
        low_risk = sum(1 for n in networks if n['risk_score'] < 30)
        
        report.append("Risk Summary:")
        report.append(f"  Critical Risk: {critical_risk}")
        report.append(f"  High Risk: {high_risk}")
        report.append(f"  Medium Risk: {medium_risk}")
        report.append(f"  Low/Very Low Risk: {low_risk}")
        report.append(f"  Total Networks: {len(networks)}")
        report.append("")
        
        # Top risky networks
        report.append("Top 5 Most Risky Networks:")
        report.append("-" * 40)
        
        for i, network in enumerate(networks[:5]):
            report.append(f"{i+1}. {network['ssid']}")
            report.append(f"   Risk: {network['risk_level']} ({network['risk_score']}/100)")
            report.append(f"   BSSID: {network['bssid']}")
            report.append(f"   Security: {network['security']}")
            report.append(f"   Signal: {network['signal_strength']} dBm ({network['signal_percent']}%)")
            report.append(f"   Channel: {network['channel']}")
            report.append("   Reasons:")
            for reason in network['risk_reasons'][:4]:  # Show top 4 reasons
                report.append(f"     • {reason}")
            report.append("")
        
        # Evil twin detection summary
        duplicate_ssids = defaultdict(list)
        for network in networks:
            duplicate_ssids[network['ssid']].append(network)
        
        evil_twin_candidates = {ssid: nets for ssid, nets in duplicate_ssids.items() if len(nets) > 1}
        
        if evil_twin_candidates:
            report.append("👥 Evil Twin Detection Summary:")
            report.append("-" * 35)
            for ssid, nets in list(evil_twin_candidates.items())[:3]:
                strongest = max(nets, key=lambda x: x['signal_strength'])
                report.append(f"  '{ssid}': {len(nets)} APs, strongest: {strongest['signal_strength']}dBm")
        
        return "\n".join(report)

# Example usage
if __name__ == "__main__":
    scanner = WiFiScanner()
    networks = scanner.scan_networks()
    
    if networks:
        report = scanner.generate_report(networks)
        print(report)
        
        # Save report to file
        with open('wifi_scan_report.txt', 'w') as f:
            f.write(report)
        print("\nReport saved to 'wifi_scan_report.txt'")