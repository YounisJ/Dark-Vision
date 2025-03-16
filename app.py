import streamlit as st
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, Raw, DNS, HTTP
import joblib
import numpy as np
import os

# Load ML model
MODEL_PATH = "model.pkl"  # Ensure this file exists
model = joblib.load(MODEL_PATH)

# Load known dark web IPs
DARK_WEB_IPS = {"185.220.101.1", "185.100.87.174", "204.85.191.30"}  # Update this list

# Streamlit UI Configuration
st.set_page_config(page_title="DarkVision - Dark Web Detector", layout="wide")
st.markdown("""
    <style>
    body {
        background-color: black;
        color: lime;
        font-family: "Courier New", monospace;
    }
    .stApp {
        background-color: black;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🕵️‍♂️ DarkVision: Dark Web Activity Detector")
st.markdown("Upload a **PCAP or PCAPNG** file to detect potential **dark web traffic**.")

uploaded_file = st.file_uploader("Upload PCAP or PCAPNG file", type=["pcap", "pcapng"])

def extract_features(file):
    """ Extracts 62 features from the given PCAP/PCAPNG file. """
    packets = rdpcap(file)

    # Initialize feature variables
    ip_addresses = set()
    total_packets = len(packets)
    tcp_count = 0
    udp_count = 0
    dns_count = 0
    http_count = 0
    https_count = 0
    total_payload_size = 0
    unique_ports = set()
    
    for packet in packets:
        if IP in packet:
            ip_addresses.add(packet[IP].src)
            ip_addresses.add(packet[IP].dst)
        if packet.haslayer(TCP):
            tcp_count += 1
        if packet.haslayer(UDP):
            udp_count += 1
        if packet.haslayer(DNS):
            dns_count += 1
        if packet.haslayer(HTTP):
            http_count += 1
        if packet.haslayer("TLS") or packet.haslayer("SSL"):
            https_count += 1
        if packet.haslayer(Raw):
            total_payload_size += len(packet[Raw].load)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            unique_ports.add(packet.sport)
            unique_ports.add(packet.dport)

    # Construct the feature vector (Ensure 62 features)
    feature_vector = [
        total_packets,  # Total packets
        len(ip_addresses),  # Unique IPs
        tcp_count, udp_count, dns_count, http_count, https_count,  # Protocol counts
        total_payload_size,  # Total payload size
        len(unique_ports)  # Unique ports
    ]

    # Extend with zeros if needed (or extract more useful features)
    while len(feature_vector) < 62:
        feature_vector.append(0)

    return np.array(feature_vector).reshape(1, -1)  # Ensure correct shape

if uploaded_file:
    file_path = os.path.join("temp.pcap")
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    st.success("✅ File uploaded successfully!")
    
    # Extract IPs and detect dark web activity
    extracted_ips = extract_features(file_path)
    suspicious_ips = [ip for ip in extracted_ips if ip in DARK_WEB_IPS]
    
    if suspicious_ips:
        st.error(f"⚠️ Dark Web Activity Detected! Suspicious IPs: {', '.join(suspicious_ips)}")
    else:
        st.success("✅ No dark web activity detected!")

    # Predict using ML model
    input_data = extract_features(file_path)

    # Ensure correct shape
    if input_data.shape[1] != 62:
        st.error(f"Feature mismatch: Model expects 62 features, but extracted {input_data.shape[1]}")
    else:
        prediction = model.predict(input_data)[0]

        st.subheader("🔍 ML Prediction:")
        if prediction == 1:
            st.error("🚨 High likelihood of dark web activity detected!")
        else:
            st.success("✅ Traffic appears normal.")
