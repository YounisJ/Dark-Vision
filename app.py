import streamlit as st
import pandas as pd
from scapy.all import rdpcap, IP
import joblib
import numpy as np
import os

# Load ML model
MODEL_PATH = "model.pkl"  # Update this path if necessary
model = joblib.load(MODEL_PATH)

# Load known dark web IPs
DARK_WEB_IPS = {"185.220.101.1", "185.100.87.174", "204.85.191.30"}  # Update with actual list

# Streamlit UI
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
    packets = rdpcap(file)
    ip_addresses = []
    
    for packet in packets:
        if IP in packet:
            ip_addresses.append(packet[IP].src)
            ip_addresses.append(packet[IP].dst)
    
    unique_ips = list(set(ip_addresses))
    return unique_ips

if uploaded_file:
    file_path = os.path.join("temp.pcap")
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    st.success("File uploaded successfully!")
    
    # Extract IPs and detect dark web activity
    extracted_ips = extract_features(file_path)
    suspicious_ips = [ip for ip in extracted_ips if ip in DARK_WEB_IPS]
    
    if suspicious_ips:
        st.error(f"⚠️ Dark Web Activity Detected! Suspicious IPs: {', '.join(suspicious_ips)}")
    else:
        st.success("No dark web activity detected!")
    
    # Predict using ML model
    # Ensure input shape matches what the model was trained on
    input_data = np.array([[len(extracted_ips)]])  # Double brackets to create a 2D array

    prediction = model.predict(input_data)[0]
    
    st.subheader("🔍 ML Prediction:")
    if prediction == 1:
        st.error("🚨 High likelihood of dark web activity detected!")
    else:
        st.success("✅ Traffic appears normal.")
