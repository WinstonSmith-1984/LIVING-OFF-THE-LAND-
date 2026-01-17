import streamlit as st
import pyshark
import plotly.graph_objects as go
import pandas as pd
import threading
import time
import requests
from collections import deque
from datetime import datetime

# --- SHARED STATE ---
class MonitorState:
    def __init__(self):
        self.risk_score = 0
        self.threat_log = deque(maxlen=15)
        self.live_feed = deque(maxlen=10)
        self.pps_history = deque([0]*30, maxlen=30)
        self.geo_data = []
        self.seen_ips = set()
        self.packet_counter = 0
        self.sensitivity = 1.0
        self.last_heartbeat = "Initializing..."
        self.is_running = True
        self.current_interface = 'any'
        self.map_all_traffic = True

if 'monitor' not in st.session_state:
    st.session_state.monitor = MonitorState()

# --- UTILITIES ---
def get_geo_location(ip, state):
    private_prefixes = ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3', '169.254.', '0.0.0.0']
    if any(ip.startswith(p) for p in private_prefixes) or ip in state.seen_ips:
        return
    
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,city,country,isp,lat,lon", timeout=2).json()
        if r.get('status') == 'success':
            entry = {
                'ip': ip,
                'location': f"{r['city']}, {r['country']}",
                'country': r.get('country', 'Unknown'),
                'isp': r.get('isp', 'Unknown'),
                'lat': r['lat'],
                'lon': r['lon']
            }
            state.geo_data.append(entry)
            state.seen_ips.add(ip)
    except:
        pass

def process_packet(pkt, state):
    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        proto = pkt.highest_layer
        src = pkt.ip.src if hasattr(pkt, 'ip') else "Internal"
        dst = pkt.ip.dst if hasattr(pkt, 'ip') else "Internal"
        state.live_feed.appendleft(f"{timestamp} | {proto} | {src} -> {dst}")
        
        if state.map_all_traffic:
            threading.Thread(target=get_geo_location, args=(src, state), daemon=True).start()

        mult = state.sensitivity
        if 'TCP' in pkt and hasattr(pkt.tcp, 'flags_reset') and pkt.tcp.flags_reset == '1':
            added_risk = 20 * mult
            state.risk_score = min(100, state.risk_score + added_risk)
            state.threat_log.appendleft(f"⚠️ TCP Reset: {src}")
    except:
        pass

# --- BACKGROUND SERVICES ---
def run_sniffer(state):
    while state.is_running:
        try:
            cap = pyshark.LiveCapture(interface=state.current_interface, display_filter="tcp.flags.reset == 1 || dns || igmp")
            for pkt in cap.sniff_continuously():
                state.packet_counter += 1
                state.last_heartbeat = datetime.now().strftime("%H:%M:%S")
                process_packet(pkt, state)
                if not state.is_running: break
        except Exception as e:
            state.last_heartbeat = f"Error: {e}"
            time.sleep(2)

def run_pps_calculator(state):
    while state.is_running:
        initial = state.packet_counter
        time.sleep(1)
        state.pps_history.append(state.packet_counter - initial)

# --- UI SETUP ---
st.set_page_config(page_title="Guardian HUD", layout="wide")

if 'started' not in st.session_state:
    threading.Thread(target=run_sniffer, args=(st.session_state.monitor,), daemon=True).start()
    threading.Thread(target=run_pps_calculator, args=(st.session_state.monitor,), daemon=True).start()
    st.session_state['started'] = True

with st.sidebar:
    st.title("🛠️ Settings")
    st.session_state.monitor.current_interface = st.selectbox("Interface", ['any', 'enp1s0', 'lo'])
    st.session_state.monitor.map_all_traffic = st.toggle("Map All External IPs", value=True)
    st.session_state.monitor.sensitivity = st.slider("Sensitivity", 0.5, 2.0, 1.0)
    
    if st.button("Reset All Stats"):
        st.session_state.monitor.risk_score = 0
        st.session_state.monitor.threat_log.clear()
        st.session_state.monitor.geo_data.clear()
        st.session_state.monitor.seen_ips.clear()
        st.rerun()
    
    st.metric("Status", "ACTIVE", delta=st.session_state.monitor.last_heartbeat)

    st.markdown("---")
    st.subheader("☕ Support the Dev")
    
    coffee_button_html = f'''
        <a href="https://www.buymeacoffee.com/WinstonSmith" target="_blank" style="text-decoration: none;">
            <div style="
                display: flex;
                align-items: center;
                justify-content: center;
                background-color: #FFDD00;
                color: black;
                padding: 12px;
                border-radius: 8px;
                font-weight: bold;
                border: 2px solid #000000;
                font-family: sans-serif;">
                ☕ Buy Me a Coffee
            </div>
        </a>
    '''
    st.markdown(coffee_button_html, unsafe_allow_html=True)
    st.write("") 
    st.caption("🛡️ System built by **WinstonSmith**")

# --- DASHBOARD HUD ---
st.title("🛡️ Network Alert Status")

col1, col2 = st.columns(2)
with col1:
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number", 
        value=st.session_state.monitor.risk_score, 
        title={'text': "Risk Level"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "black"},
            'steps': [
                {'range': [0, 35], 'color': "#2ecc71"},
                {'range': [35, 75], 'color': "#f39c12"},
                {'range': [75, 100], 'color': "#e74c3c"}
            ]
        }
    ))
    fig_gauge.update_layout(height=250, margin=dict(t=50, b=0))
    st.plotly_chart(fig_gauge, use_container_width=True)

with col2:
    fig_pps = go.Figure(go.Scatter(y=list(st.session_state.monitor.pps_history), fill='tozeroy', line_color='#3498db'))
    fig_pps.update_layout(height=250, margin=dict(t=50, b=0), title="Packets Per Second")
    st.plotly_chart(fig_pps, use_container_width=True)

map_col, data_col = st.columns([1.5, 1])
with map_col:
    st.caption("🌍 Traffic Origin Map")
    if st.session_state.monitor.geo_data:
        st.map(pd.DataFrame(st.session_state.monitor.geo_data), height=350)
    else:
        st.info("Listening for external traffic...")

with data_col:
    st.caption("🔍 Origin Identity (WhoIs)")
    if st.session_state.monitor.geo_data:
        df_geo = pd.DataFrame(st.session_state.monitor.geo_data)
        st.dataframe(df_geo.tail(5)[['ip', 'isp']], hide_index=True, use_container_width=True, height=150)
        
        st.caption("🏁 Traffic by Country & ISP")
        # UPDATED: Aggregating Country + ISP
        summary_df = df_geo.groupby('country').agg({
            'ip': 'count',
            'isp': lambda x: ', '.join(x.unique())
        }).reset_index()
        summary_df.columns = ['Country', 'Packet Count', 'Detected ISPs']
        st.dataframe(summary_df.sort_values(by='Packet Count', ascending=False), hide_index=True, use_container_width=True, height=200)
    else:
        st.write("No external IPs logged.")

with st.expander("🚨 Threat Logs"):
    if not st.session_state.monitor.threat_log: st.write("Clean.")
    for entry in st.session_state.monitor.threat_log: st.error(entry)

with st.expander("📡 Raw Feed"):
    for p in st.session_state.monitor.live_feed: st.code(p)

if st.session_state.monitor.risk_score >= 50:
    st.toast("HIGH RISK ALERT", icon="🚨")

time.sleep(2)
st.rerun()
