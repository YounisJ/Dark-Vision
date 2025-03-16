import streamlit as st
import pyshark
import pandas as pd
import joblib
import os

st.set_page_config(page_title="Dark Web Detector", layout="wide")
st.title("💀 Dark Web Traffic Detector")

# Load the trained model
model = joblib.load("tor_detector.pkl")

# Known Dark Web IPs (Example List) — Ideally, fetch dynamically from threat sources
dark_web_ips = {
    "185.220.101.1", "185.220.101.2", "185.220.101.3",  # Example Tor nodes
    "171.25.193.20", "104.244.72.115"  # More suspicious IPs
}

# Function to extract features from PCAP/PCAPNG
def extract_features(file_path):
    cap = pyshark.FileCapture(file_path)

    features = []
    for packet in cap:
        try:
            source_ip = packet.ip.src if hasattr(packet, 'ip') else None
            dest_ip = packet.ip.dst if hasattr(packet, 'ip') else None
            
            features.append({
                'timestamp': float(packet.sniff_time.timestamp()),
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'protocol': packet.highest_layer,
                'length': int(packet.length),
                'tcp_flags': packet.tcp.flags if hasattr(packet, 'tcp') else None
            })
        except AttributeError:
            continue  # Skip packets with missing attributes

    cap.close()
    return pd.DataFrame(features)

# File upload in Streamlit
uploaded_file = st.file_uploader("Upload PCAP or PCAPNG file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Save uploaded file temporarily
    file_path = "uploaded_file.pcapng"
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # Extract features
    st.info("Processing file... Please wait!")
    df = extract_features(file_path)

    if df.empty:
        st.error("No valid network packets found. Try another file.")
    else:
        # Drop unnecessary columns
        X_input = df.drop(columns=['timestamp'], errors="ignore")

        # Make predictions
        predictions = model.predict(X_input)
        df['Tor_Detected'] = predictions

        # Find suspicious IPs
        detected_ips = set(df[df["Tor_Detected"] == 1]["source_ip"]).union(set(df[df["Tor_Detected"] == 1]["destination_ip"]))
        dark_web_activity = detected_ips.intersection(dark_web_ips)

        if dark_web_activity:
            st.error("🚨 Dark Web Activity Detected! 🚨")
            st.write(f"⚠️ **Suspicious IPs:** {', '.join(dark_web_activity)}")
        else:
            st.success("No Dark Web Activity Found.")

        # Show results
        st.dataframe(df[['source_ip', 'destination_ip', 'protocol', 'Tor_Detected']])

        # Cleanup
        os.remove(file_path)
