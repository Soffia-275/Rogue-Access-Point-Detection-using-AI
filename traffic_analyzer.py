#traffic_analyzer.py
import time
from collections import defaultdict, deque
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Dot11, Dot11Beacon, Dot11Elt, RadioTap, Ether
import socket
import threading
from datetime import datetime
import pandas as pd
import joblib
import warnings
warnings.filterwarnings('ignore')

try:
    import tensorflow as tf
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("Warning: TensorFlow not available. AI features disabled.")

class EvilTwinDetector:
    def __init__(self):
        self.traffic_model = None
        self.traffic_scaler = None
        self.model_loaded = False
        self.load_model()

    def load_model(self):
        """Load the trained model and scaler"""
        try:
            self.traffic_model = tf.keras.models.load_model('traffic_model.h5')
            self.traffic_scaler = joblib.load('traffic_scaler.pkl')
            self.model_loaded = True
            print("AI Model loaded successfully for evil twin detection")
        except Exception as e:
            print(f"Error loading model: {e}")
            print("Please make sure you've trained the model first using model.py")
            self.model_loaded = False

    def analyze_network_traffic(self, feature_dict):
        if not self.model_loaded:
            return {'error': "Model not loaded. Please train first."}
        try:
            # Convert feature dict to DataFrame
            feature_df = pd.DataFrame([feature_dict])
            
            # Ensure all expected features are present
            if hasattr(self.traffic_scaler, 'feature_names_in_'):
                for feature in self.traffic_scaler.feature_names_in_:
                    if feature not in feature_df.columns:
                        feature_df[feature] = 0
                feature_df = feature_df[self.traffic_scaler.feature_names_in_].fillna(0)
            
            # Clean the data
            for col in feature_df.columns:
                feature_df[col] = pd.to_numeric(feature_df[col], errors='coerce')
            feature_df = feature_df.replace([np.inf, -np.inf], 0)
            feature_df = feature_df.fillna(0)
            
            # Scale features
            feature_scaled = self.traffic_scaler.transform(feature_df)
            
            # Reshape for CNN/LSTM if needed
            if len(self.traffic_model.input_shape) == 3:
                feature_scaled = feature_scaled.reshape(feature_scaled.shape[0], feature_scaled.shape[1], 1)
            
            # Make prediction
            prediction_prob = self.traffic_model.predict(feature_scaled, verbose=0)[0][0]
            
            # Interpret results
            if prediction_prob > 0.7:
                is_evil_twin = True
                safety_score = (1 - prediction_prob) * 100
            elif prediction_prob < 0.3:
                is_evil_twin = False
                safety_score = (1 - prediction_prob) * 100
            else:
                is_evil_twin = prediction_prob > 0.5
                safety_score = 50

            # Generate recommendation
            if is_evil_twin:
                if safety_score < 30:
                    recommendation = "EVIL TWIN DETECTED! Disconnect immediately!"
                else:
                    recommendation = "Suspicious network detected. Proceed with caution."
            else:
                if safety_score >= 80:
                    recommendation = "Network appears safe."
                else:
                    recommendation = "Network shows minor anomalies."

            return {
                'safety_score': round(safety_score, 2),
                'safety_level': "SAFE" if safety_score >= 70 else "CAUTION" if safety_score >= 50 else "UNSAFE",
                'recommendation': recommendation,
                'is_evil_twin': bool(is_evil_twin),
                'probability_evil_twin': f"{prediction_prob:.2%}",
                'probability_legitimate': f"{(1-prediction_prob):.2%}"
            }
        except Exception as e:
            return {'error': f"Analysis failed: {e}"}

class Flow:
    """Network flow analysis"""
    def __init__(self, packet, local_ip):
        self.packets = deque([packet], maxlen=1000)
        self.start_time = packet.time
        self.end_time = packet.time
        self.local_ip = local_ip
        self.protocol = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
        self.dns_queries = []
        self.ports = set()
        self.wireless_packets = []
        
    def add_packet(self, packet):
        self.packets.append(packet)
        self.end_time = packet.time
        
        # Check for wireless packets (for evil twin detection)
        if Dot11 in packet:
            self.wireless_packets.append(packet)
        
        if DNS in packet and DNSQR in packet:
            self.dns_queries.append(packet[DNSQR].qname.decode() if hasattr(packet[DNSQR].qname, 'decode') else str(packet[DNSQR].qname))
        
        if TCP in packet:
            self.ports.add(packet[TCP].sport)
            self.ports.add(packet[TCP].dport)
        elif UDP in packet:
            self.ports.add(packet[UDP].sport)
            self.ports.add(packet[UDP].dport)

    def get_wireless_features(self):
        """Extract wireless-specific features for evil twin detection"""
        if not self.wireless_packets:
            return {}
            
        beacon_count = 0
        ssids = set()
        channels = set()
        signal_strengths = []
        encryption_types = set()
        
        for packet in self.wireless_packets:
            if Dot11Beacon in packet:
                beacon_count += 1
                
                # Extract SSID
                if packet[Dot11Elt].ID == 0:  # SSID
                    try:
                        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                        if ssid and ssid.strip():
                            ssids.add(ssid)
                    except:
                        pass
                
                # Extract channel
                if packet[Dot11Elt].ID == 3:  # DS Parameter Set (channel)
                    try:
                        channels.add(packet[Dot11Elt].info[0])
                    except:
                        pass
                
                # Signal strength
                if RadioTap in packet:
                    if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                        signal_strengths.append(packet[RadioTap].dBm_AntSignal)
            
            # Extract encryption info
            if Dot11Elt in packet:
                if packet[Dot11Elt].ID == 48:  # RSN Information
                    encryption_types.add('WPA2')
                elif packet[Dot11Elt].ID == 221:  # Vendor Specific
                    if b'WPA' in packet[Dot11Elt].info:
                        encryption_types.add('WPA')
        
        return {
            'beacon_count': beacon_count,
            'unique_ssids': len(ssids),
            'unique_channels': len(channels),
            'avg_signal_strength': np.mean(signal_strengths) if signal_strengths else -100,
            'encryption_types': len(encryption_types),
            'ssid_changes': len(ssids) > 1  # Multiple SSIDs from same MAC
        }

    def get_features(self):
        """Extract features for AI analysis"""
        if len(self.packets) < 2:
            return None

        duration_sec = self.end_time - self.start_time
        if duration_sec == 0:
            duration_sec = 1e-6

        fwd_packets = [p for p in self.packets if IP in p and p[IP].src == self.local_ip]
        bwd_packets = [p for p in self.packets if IP in p and p[IP].dst == self.local_ip]

        fwd_lengths = [len(p) for p in fwd_packets]
        bwd_lengths = [len(p) for p in bwd_packets]
        
        tcp_fwd = [p for p in fwd_packets if TCP in p]
        tcp_bwd = [p for p in bwd_packets if TCP in p]

        # Get wireless features
        wireless_features = self.get_wireless_features()

        features = {
            'Flow Duration': duration_sec * 1_000_000,
            'Total Fwd Packets': len(fwd_packets),
            'Total Backward Packets': len(bwd_packets),
            'Total Length of Fwd Packets': sum(fwd_lengths),
            'Total Length of Bwd Packets': sum(bwd_lengths),
            
            'Fwd Packet Length Mean': np.mean(fwd_lengths) if fwd_lengths else 0,
            'Bwd Packet Length Mean': np.mean(bwd_lengths) if bwd_lengths else 0,
            'Fwd Packet Length Std': np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0,
            'Bwd Packet Length Std': np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0,
            'Fwd Packet Length Max': max(fwd_lengths) if fwd_lengths else 0,
            'Bwd Packet Length Max': max(bwd_lengths) if bwd_lengths else 0,
            'Fwd Packet Length Min': min(fwd_lengths) if fwd_lengths else 0,
            'Bwd Packet Length Min': min(bwd_lengths) if bwd_lengths else 0,
            
            'Flow Packets/s': len(self.packets) / duration_sec,
            'Fwd Packets/s': len(fwd_packets) / duration_sec,
            'Bwd Packets/s': len(bwd_packets) / duration_sec,
            'Flow Bytes/s': (sum(fwd_lengths) + sum(bwd_lengths)) / duration_sec,
            
            'Fwd PSH Flags': sum(1 for p in tcp_fwd if TCP in p and 'P' in p[TCP].flags),
            'Bwd PSH Flags': sum(1 for p in tcp_bwd if TCP in p and 'P' in p[TCP].flags),
            'Fwd URG Flags': sum(1 for p in tcp_fwd if TCP in p and 'U' in p[TCP].flags),
            'Bwd URG Flags': sum(1 for p in tcp_bwd if TCP in p and 'U' in p[TCP].flags),
            'Fwd FIN Flags': sum(1 for p in tcp_fwd if TCP in p and 'F' in p[TCP].flags),
            'Bwd FIN Flags': sum(1 for p in tcp_bwd if TCP in p and 'F' in p[TCP].flags),
            'Fwd SYN Flags': sum(1 for p in tcp_fwd if TCP in p and 'S' in p[TCP].flags),
            'Bwd SYN Flags': sum(1 for p in tcp_bwd if TCP in p and 'S' in p[TCP].flags),
            'Fwd RST Flags': sum(1 for p in tcp_fwd if TCP in p and 'R' in p[TCP].flags),
            'Bwd RST Flags': sum(1 for p in tcp_bwd if TCP in p and 'R' in p[TCP].flags),
            
            'Init_Win_bytes_forward': next((p[TCP].window for p in tcp_fwd if TCP in p), 0),
            'Init_Win_bytes_backward': next((p[TCP].window for p in tcp_bwd if TCP in p), 0),
            
            'bytes_ratio': sum(fwd_lengths) / sum(bwd_lengths) if sum(bwd_lengths) > 0 else 1,
            'traffic_asymmetry': abs((sum(fwd_lengths) / sum(bwd_lengths) if sum(bwd_lengths) > 0 else 1) - 1),
            'packets_ratio': len(fwd_packets) / len(bwd_packets) if len(bwd_packets) > 0 else 1,
            'avg_packet_size': (sum(fwd_lengths) + sum(bwd_lengths)) / len(self.packets),
            
            'avg_fwd_segment_size': np.mean(fwd_lengths) if fwd_lengths else 0,
            'avg_bwd_segment_size': np.mean(bwd_lengths) if bwd_lengths else 0,
            'fwd_header_length': sum(len(p[TCP]) if TCP in p else 0 for p in fwd_packets),
            'subflow_fwd_packets': len(fwd_packets) // 2,
            'subflow_bwd_packets': len(bwd_packets) // 2,
            'subflow_fwd_bytes': sum(fwd_lengths) // 2,
            'subflow_bwd_bytes': sum(bwd_lengths) // 2,
            
            'dns_query_count': len(self.dns_queries),
            'unique_ports': len(self.ports),
            
            # Evil twin specific features
            'beacon_frame_count': wireless_features.get('beacon_count', 0),
            'multiple_ssids': 1 if wireless_features.get('ssid_changes', False) else 0,
            'signal_strength_variance': wireless_features.get('avg_signal_strength', -100),
            'channel_changes': wireless_features.get('unique_channels', 0),
            'encryption_inconsistencies': 1 if wireless_features.get('encryption_types', 0) > 1 else 0,
            'authentication_failures': sum(1 for p in self.packets if TCP in p and p[TCP].dport in [80, 443] and 'R' in p[TCP].flags),
            'dns_anomalies': 1 if any('fake' in query.lower() or 'evil' in query.lower() or 'phish' in query.lower() for query in self.dns_queries) else 0
        }
        
        return features

class TrafficAnalyzer:
    def __init__(self):
        self.flows = defaultdict(lambda: None)
        self.local_ip = self.get_local_ip()
        self.capture_stats = {
            'total_packets': 0,
            'total_flows': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Initialize AI model for evil twin detection
        if AI_AVAILABLE:
            self.evil_twin_detector = EvilTwinDetector()
            self.ai_model_loaded = self.evil_twin_detector.model_loaded
        else:
            self.ai_model_loaded = False
            print("⚠️ TensorFlow not available - evil twin detection disabled")

    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def get_flow_key(self, packet):
        """Generate unique flow key"""
        if IP not in packet:
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        else:
            return None
            
        if src_ip < dst_ip:
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
        return key

    def packet_handler(self, packet):
        """Handle incoming packets"""
        self.capture_stats['total_packets'] += 1
        
        if IP not in packet and Dot11 not in packet:
            return
            
        flow_key = self.get_flow_key(packet) if IP in packet else "wireless"
        if not flow_key:
            return
            
        if self.flows[flow_key] is None:
            self.flows[flow_key] = Flow(packet, self.local_ip)
            self.capture_stats['total_flows'] += 1
        else:
            self.flows[flow_key].add_packet(packet)

    def detect_evil_twin(self, features):
        """Use AI model to detect evil twin attacks"""
        if not self.ai_model_loaded:
            return {
                'error': 'AI model not loaded',
                'is_evil_twin': False,
                'safety_score': 0,
                'recommendation': 'AI model not available'
            }
        
        try:
            result = self.evil_twin_detector.analyze_network_traffic(features)
            return result
        except Exception as e:
            return {
                'error': f'AI analysis failed: {e}',
                'is_evil_twin': False,
                'safety_score': 0,
                'recommendation': 'Check model configuration'
            }

    def capture_traffic(self, duration=60, packet_count=10000):
        """Capture network traffic"""
        print(f"Starting traffic capture for {duration}s...")
        print("🔍 Evil twin detection enabled" if self.ai_model_loaded else "⚠️ Evil twin detection disabled")
        
        self.capture_stats['start_time'] = datetime.now()
        
        stop_event = threading.Event()
        
        def stop_capture():
            time.sleep(duration)
            stop_event.set()
            
        timer_thread = threading.Thread(target=stop_capture)
        timer_thread.daemon = True
        timer_thread.start()
        
        # Capture both wired and wireless traffic
        sniff(prn=self.packet_handler, stop_filter=lambda x: stop_event.is_set(), count=packet_count)
        
        self.capture_stats['end_time'] = datetime.now()
        
        print(f"Capture complete. Processed {self.capture_stats['total_packets']} packets, {len(self.flows)} flows.")
        return self.extract_features()

    def extract_features(self):
        """Extract features from all flows and run evil twin detection"""
        features_list = []
        evil_twin_results = []
        valid_flows = 0
        
        for flow_key, flow in self.flows.items():
            if flow and len(flow.packets) >= 2:
                features = flow.get_features()
                if features:
                    features_list.append(features)
                    valid_flows += 1
                    
                    # Run evil twin detection on this flow
                    if self.ai_model_loaded:
                        detection_result = self.detect_evil_twin(features)
                        detection_result['flow_key'] = flow_key
                        detection_result['packet_count'] = len(flow.packets)
                        evil_twin_results.append(detection_result)
        
        print(f"Extracted features from {valid_flows} valid flows.")
        
        # Analyze overall evil twin risk
        overall_risk = self.analyze_overall_risk(evil_twin_results)
        
        return {
            'features': features_list,
            'evil_twin_analysis': evil_twin_results,
            'overall_risk': overall_risk
        }

    def analyze_overall_risk(self, evil_twin_results):
        """Analyze overall network risk based on evil twin detection results"""
        if not evil_twin_results:
            return {
                'overall_safety_score': 100,
                'risk_level': 'LOW',
                'evil_twin_detected': False,
                'suspicious_flows': 0,
                'recommendation': 'No suspicious activity detected'
            }
        
        high_risk_flows = sum(1 for result in evil_twin_results 
                             if result.get('is_evil_twin', False) and 
                                result.get('safety_score', 100) < 30)
        
        medium_risk_flows = sum(1 for result in evil_twin_results 
                               if result.get('safety_score', 100) < 70 and 
                                  not result.get('is_evil_twin', False))
        
        safety_scores = [result.get('safety_score', 100) for result in evil_twin_results 
                        if 'safety_score' in result and not isinstance(result.get('safety_score'), str)]
        
        avg_safety_score = np.mean(safety_scores) if safety_scores else 100
        
        if high_risk_flows > 0:
            risk_level = 'CRITICAL'
            recommendation = '🚨 EVIL TWIN DETECTED! Disconnect immediately!'
        elif medium_risk_flows > 2:
            risk_level = 'HIGH'
            recommendation = 'Multiple suspicious flows detected. Avoid sensitive activities.'
        elif avg_safety_score < 70:
            risk_level = 'MEDIUM'
            recommendation = 'Network shows some anomalies. Proceed with caution.'
        else:
            risk_level = 'LOW'
            recommendation = 'Network appears safe.'
        
        return {
            'overall_safety_score': round(avg_safety_score, 2),
            'risk_level': risk_level,
            'evil_twin_detected': high_risk_flows > 0,
            'suspicious_flows': high_risk_flows + medium_risk_flows,
            'high_risk_flows': high_risk_flows,
            'medium_risk_flows': medium_risk_flows,
            'recommendation': recommendation
        }

    def get_statistics(self):
        """Get capture statistics"""
        duration = (self.capture_stats['end_time'] - self.capture_stats['start_time']).total_seconds()
        packets_per_second = self.capture_stats['total_packets'] / duration if duration > 0 else 0
        
        stats = {
            'capture_duration': f"{duration:.2f}s",
            'total_packets': self.capture_stats['total_packets'],
            'total_flows': len(self.flows),
            'packets_per_second': f"{packets_per_second:.2f}",
            'average_flow_length': f"{self.capture_stats['total_packets'] / len(self.flows) if self.flows else 0:.2f}",
            'ai_model_loaded': self.ai_model_loaded
        }
        
        return stats

    def print_evil_twin_report(self, analysis_results):
        """Print a detailed evil twin detection report"""
        if 'evil_twin_analysis' not in analysis_results:
            return
            
        print("\n" + "="*60)
        print("🔍 EVIL TWIN DETECTION REPORT")
        print("="*60)
        
        overall_risk = analysis_results.get('overall_risk', {})
        
        print(f"Overall Safety Score: {overall_risk.get('overall_safety_score', 'N/A')}%")
        print(f"Risk Level: {overall_risk.get('risk_level', 'UNKNOWN')}")
        print(f"Evil Twin Detected: {'YES 🚨' if overall_risk.get('evil_twin_detected') else 'No ✅'}")
        print(f"Suspicious Flows: {overall_risk.get('suspicious_flows', 0)}")
        print(f"Recommendation: {overall_risk.get('recommendation', 'N/A')}")
        
        if analysis_results['evil_twin_analysis']:
            print("\nDetailed Flow Analysis:")
            print("-" * 40)
            
            for i, result in enumerate(analysis_results['evil_twin_analysis'][:5]):  # Show top 5
                if 'error' not in result:
                    print(f"Flow {i+1}: Safety={result.get('safety_score', 'N/A')}% | "
                          f"Evil Twin: {result.get('is_evil_twin', False)} | "
                          f"Packets: {result.get('packet_count', 0)}")

# Example usage
if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    
    # Capture traffic for 30 seconds
    results = analyzer.capture_traffic(duration=30)
    
    # Print statistics
    stats = analyzer.get_statistics()
    print("\nCapture Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Print evil twin report
    analyzer.print_evil_twin_report(results)