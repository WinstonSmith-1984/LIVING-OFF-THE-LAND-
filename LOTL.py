import streamlit as st
import pyshark
import plotly.express as px
import pandas as pd
import threading
import time
import os
import re
from collections import deque, Counter
from datetime import datetime
import io

# =============================================================================
# LOTL-LAN 🦀
# Version: 1.9.57 "Active Response"
# Build: Jan 2026 
# Design: WinstonSmith_1984
# License: GNU General Public License v3
# =============================================================================

class MonitorState:
    def __init__(self):
        self.live_feed = deque(maxlen=20) 
        self.threat_log = [] 
        self.proto_counts = Counter()
        self.unique_ips = set()
        self.is_running = True
        self.current_interface = 'any'
        self.gateway_ip = "0.0.0.0"

if 'monitor' not in st.session_state:
    st.session_state.monitor = MonitorState()

# --- 🔍 SNIFFER ENGINE ---
def run_sniffer(state):
    while state.is_running:
        try:
            with pyshark.LiveCapture(interface=state.current_interface) as cap:
                for pkt in cap.sniff_continuously(packet_count=1):
                    if not hasattr(pkt, 'ip') and not hasattr(pkt, 'ipv6'): continue
                    proto = pkt.highest_layer
                    ts = datetime.now().strftime('%H:%M:%S')
                    src = pkt.ip.src if hasattr(pkt, 'ip') else pkt.ipv6.src
                    dst = pkt.ip.dst if hasattr(pkt, 'ip') else pkt.ipv6.dst
                    state.proto_counts[proto] += 1
                    state.live_feed.appendleft(f"{ts} | {proto: <6} | {src} -> {dst}")
                    if src.startswith('192.168.') and dst.startswith('192.168.'):
                        threat_str = f"⚠️ {src} -> {dst} ({proto})"
                        if threat_str not in state.threat_log:
                            state.threat_log.insert(0, threat_str)
                            if len(state.threat_log) > 100: state.threat_log.pop()
        except: time.sleep(2) 

if 'started' not in st.session_state:
    threading.Thread(target=run_sniffer, args=(st.session_state.monitor,), daemon=True).start()
    st.session_state['started'] = True

# --- 🎨 UI STYLING ---
st.set_page_config(page_title="LOTL-LAN 🦀", layout="wide")
st.markdown("""
<style>
    .block-container { padding-top: 75px !important; }
    .alert-box { padding: 12px; border-radius: 8px; text-align: center; font-weight: 800; border: 2px solid transparent; margin-bottom: 10px; }
    .safe { background: rgba(0, 255, 136, 0.1); color: #00FF88; border-color: #00FF88; }
    .danger { background: rgba(255, 75, 75, 0.1); color: #FF4B4B; border-color: #FF4B4B; animation: pulse 2s infinite; }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
    .stCodeBlock pre { height: 100px !important; max-height: 100px !important; overflow-y: auto !important; border: 1px solid #333; }
    .threat-window { height: 300px; overflow-y: scroll; font-size: 0.85rem; color: #FF4B4B; background: rgba(255, 75, 75, 0.05); border: 1px solid rgba(255, 75, 75, 0.3); padding: 15px; border-radius: 5px; font-family: monospace; white-space: pre-line; }
    .donation-container { margin-top: 5cm; text-align: center; padding: 16px; border-radius: 10px; background: rgba(255, 253, 208, 0.05); border: 1px solid rgba(255, 253, 208, 0.12); }
    .inverted-button { display: inline-block; background: #1C1C1E; color: #FFFDD0 !important; padding: 13px 31px; border-radius: 7px; text-decoration: none; border: 2px solid #FFFDD0; }
    .coffee-hd { font-size: 2.25em; vertical-align: middle; }
    .license-info { margin-top: 20px; font-size: 0.65rem; color: #777; text-align: center; border-top: 1px solid #333; padding-top: 12px; line-height: 1.4; }
</style>
""", unsafe_allow_html=True)

# --- CSV UTILITY ---
def convert_log_to_csv(log_data):
    rows = []
    for entry in log_data:
        match = re.search(r'⚠️ ([\d\.]+) -> ([\d\.]+) \((.+)\)', entry)
        if match:
            rows.append({"Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Source": match.group(1), "Destination": match.group(2), "Protocol": match.group(3)})
    return pd.DataFrame(rows).to_csv(index=False).encode('utf-8')

# --- SIDEBAR ---
with st.sidebar:
    st.title("LOTL-LAN 🦀")
    st.caption("v1.9.57 Active Response")
    st.selectbox("Interface", ['any', 'lo', 'wlan0', 'eth0'], key="iface_selector")
    st.markdown(f'<div class="donation-container"><a href="https://paypal.me/conlon1984" target="_blank" class="inverted-button"><span class="coffee-hd">☕</span></a><div class="license-info"><b>GNU GENERAL PUBLIC LICENSE v3</b><br>© 2026 WinstonSmith_1984</div></div>', unsafe_allow_html=True)

# --- PROTOCOL INTELLIGENCE ---
def get_proto_intel(proto):
    intel = {
        "NBNS": "NetBIOS Name Service. **Vector:** Targeted for NBNS Spoofing. **Action:** WILL Analyze frequency for lateral pivot patterns and alert accordingly in the System Security Status window.",
        "LLMNR": "Link-Local Multicast Name Resolution. **Vector:** NTLM hash theft. **Action:** WILL Analyze frequency for lateral pivot patterns and alert accordingly in the System Security Status window.",
        "MDNS": "Multicast DNS. **Vector:** Reconnaissance/Discovery. **Action:** WILL Analyze frequency for lateral pivot patterns and alert accordingly in the System Security Status window.",
        "ARP": "Address Resolution Protocol. **Vector:** MitM via Cache Poisoning. **Action:** WILL Analyze frequency for lateral pivot patterns and alert accordingly in the System Security Status window."
    }
    return intel.get(proto.upper(), "Standard internal traffic. **Action:** WILL Analyze frequency for lateral pivot patterns and alert accordingly in the System Security Status window.")

# --- MAIN HUD ---
@st.fragment(run_every=5)
def main_hud():
    m = st.session_state.monitor
    
    # DYNAMIC SECURITY STATUS
    is_active_threat = len(st.session_state.get('tagged_threats', [])) > 0
    with st.expander("🛡️ SYSTEM SECURITY STATUS", expanded=True):
        cols = st.columns(4)
        status_labels = ["ARP", "SCAN", "HOST", "DECOY"]
        for i, label in enumerate(status_labels):
            # If threat is tagged, "SCAN" and "HOST" flip to alert
            if is_active_threat and label in ["SCAN", "HOST"]:
                col_type = "danger"
                col_text = f"{label}: ⚠️ ALERT"
            else:
                col_type = "safe"
                col_text = f"{label}: ✅ SECURE"
            cols[i].markdown(f'<div class="alert-box {col_type}">{col_text}</div>', unsafe_allow_html=True)

    left, right = st.columns([1, 1])
    with left:
        st.markdown("### 📊 Network Protocols")
        with st.expander("Protocol Distribution Chart", expanded=True):
            if m.proto_counts:
                fig_pie = px.pie(names=list(m.proto_counts.keys()), values=list(m.proto_counts.values()), hole=0.4)
                fig_pie.update_layout(margin=dict(t=20, b=20, l=0, r=0), height=280, paper_bgcolor='rgba(0,0,0,0)', legend=dict(font=dict(size=14)))
                st.plotly_chart(fig_pie, width='stretch')
        with st.expander("🔍 Analysis Window (Live Stream)", expanded=False):
            st.code("\n".join(list(m.live_feed)) or "Monitoring...", language="text")

    with right:
        st.markdown("### 🚩 Lateral Movement")
        with st.expander("East-West Threat Window", expanded=True):
            threat_content = "\n".join(m.threat_log) if m.threat_log else "Clean telemetry."
            st.markdown(f'<div class="threat-window">{threat_content}</div>', unsafe_allow_html=True)
        
        st.markdown("### 🔍 Threat Analysis Log")
        if m.threat_log:
            csv_data = convert_log_to_csv(m.threat_log)
            st.download_button("💾 SAVE LOG TO CSV", csv_data, f"lotl_threat_log_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", "text/csv", use_container_width=True)

        selected_conns = []
        with st.expander("Tag Internal Threats", expanded=True):
            for conn in sorted(m.threat_log):
                if st.checkbox(f"Tag: {conn.replace('⚠️ ', '')}", key=f"chk_{conn}"):
                    selected_conns.append(conn)
        st.session_state['tagged_threats'] = selected_conns

        if selected_conns:
            with st.expander("📝 Threat Intelligence", expanded=True):
                for conn in selected_conns:
                    proto_match = re.search(r'\((.+)\)', conn)
                    proto = proto_match.group(1) if proto_match else "Unknown"
                    st.error(f"**Host Analyst: {conn.replace('⚠️ ', '')}**")
                    st.info(get_proto_intel(proto))

main_hud()
