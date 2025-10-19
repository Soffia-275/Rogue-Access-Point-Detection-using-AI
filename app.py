#app.py
import streamlit as st
import pandas as pd
import numpy as np
import os
from model import EvilTwinDetector
from wifi_scanner import WiFiScanner
from traffic_analyzer import TrafficAnalyzer

st.set_page_config(
    page_title="Rogue Access Point Detection",
    layout="wide",
    page_icon="🛡️"
)

class EvilTwinApp:
    def __init__(self):
        self.wifi_scanner = WiFiScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detector = None
        self.load_detector()
        
    def load_detector(self):
        """Load the AI model"""
        try:
            self.detector = EvilTwinDetector()
            if self.detector.model_loaded:
                st.sidebar.success("Model Loaded")
            else:
                st.sidebar.error("❌ AI Model Not Trained")
        except:
            st.sidebar.error("❌ AI Model Not Available")

    def run(self):
        st.title("Rogue Access Point Detection")
        
        st.sidebar.title("Navigation")
        page = st.sidebar.radio("Go to", ["Dashboard", "WiFi Scan", "Traffic Analysis"])
        
        if page == "Dashboard":
            self.show_dashboard()
        elif page == "WiFi Scan":
            self.show_wifi_scan()
        elif page == "Traffic Analysis":
            self.show_traffic_analysis()
    
    def show_dashboard(self):
        st.header("Dashboard")
        
        # Check model status
        model_exists = os.path.exists('traffic_model.h5')
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("AI Model", "✅ Ready" if model_exists else "❌ Not Trained")
        with col2:
            st.metric("WiFi Scanner", "✅ Ready")
        with col3:
            st.metric("Traffic Analyzer", "✅ Ready")
        
        if not model_exists:
            st.error("""
            **AI Model Not Trained!**
            
            Please train the model first:
            ```bash
            python train.py
            ```
            """)
        
        st.info("""
        **How to use:**
        1. Train the AI model (if not already done)
        2. Scan WiFi networks for suspicious SSIDs
        3. Analyze network traffic for Evil Twin patterns
        """)
    
    def show_wifi_scan(self):
        st.header("WiFi Network Scanner")
        
        if st.button("Scan WiFi Networks"):
            with st.spinner("Scanning..."):
                networks = self.wifi_scanner.scan_networks()
                
            if networks:
                st.success(f"Found {len(networks)} networks")
                
                for network in networks:
                    with st.expander(f"{network['ssid']} - {network['risk_level']}"):
                        st.write(f"**Security:** {network['security']}")
                        st.write(f"**Signal:** {network['signal_strength']} dBm")
                        st.write(f"**Risk Score:** {network['risk_score']}/100")
            else:
                st.error("No networks found or scan failed")
    
    def show_traffic_analysis(self):
        st.header("Network Traffic Analysis")
        
        if not self.detector or not self.detector.model_loaded:
            st.error("AI model not trained. Please run `python train.py` first.")
            return
        
        st.warning("Connect to a WiFi network first, then start analysis.")
        
        if st.button("Start Traffic Analysis"):
            with st.spinner("Capturing traffic for 30 seconds..."):
                features_list = self.traffic_analyzer.capture_traffic(duration=30)
                
            if features_list:
                st.success(f"Analyzing {len(features_list)} network flows...")
                
                results = []
                for features in features_list:
                    result = self.detector.analyze_network_traffic(features)
                    if 'error' not in result:
                        results.append(result)
                
                # Show worst result
                if results:
                    worst = min(results, key=lambda x: x['safety_score'])
                    
                    st.subheader("Analysis Result")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Safety Score", f"{worst['safety_score']}%")
                        st.metric("Safety Level", worst['safety_level'])
                    with col2:
                        st.metric("Evil Twin", "Yes" if worst['is_evil_twin'] else "No")
                        st.metric("Evil Twin Probability", worst['probability_evil_twin'])
                    
                    st.write(f"**Recommendation:** {worst['recommendation']}")
                else:
                    st.error("No valid traffic flows analyzed")
            else:
                st.error("No traffic captured. Please try again.")

if __name__ == "__main__":
    app = EvilTwinApp()
    app.run()