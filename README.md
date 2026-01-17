for all those targeted individuals under repressive regimes -the "Winston Smiths"  a way to passively monitor their internet connection for signs of bad actor snooping, state or otherwise. 
Developed on Linux Mint "22.3 (Zena)" 


A real-time network security monitoring dashboard built with Python, Streamlit, and PyShark. Designed for Linux users to visualize incoming traffic and detect potential threats.

🚀 Key Features

    Live Traffic Sniffing: Captures real-time packets using pyshark on specified interfaces.

    Risk Scoring System: Dynamically calculates threat levels based on TCP Reset flags and packet behavior.

    Geographic IP Mapping: Automatically resolves external IP addresses to physical locations (City/Country) and maps them in real-time.

    Visual Analytics: * Gauge Chart: Instant visualization of current risk levels.

        PPS History: Real-time graph showing "Packets Per Second" to detect spikes.

    WHOIS Intelligence: Displays ISP and Country data for incoming external traffic.

    Alerting System: Features a "Threat Log" and high-risk browser notifications (toasts).

### 🔍 Detection Logic Summary

| Feature | Detection Method | Logic / Threshold | Potential Threat |
| :--- | :--- | :--- | :--- |
| **Connection Termination** | **TCP Reset (`RST`)** | `tcp.flags.reset == 1` | Port Scanning, Hijacking, or Server Instability. |
| **Volumetric Analysis** | **PPS Tracking** | Calculates Packets Per Second | DoS/DDoS attacks or high-frequency probing. |
| **Geographic Risks** | **IP Geolocation** | Filters private ranges; maps external IPs | Unauthorized access from unexpected regions. |
| **Protocol Filtering** | **Specific Capture** | `TCP RST`, `DNS`, and `IGMP` | DNS Tunneling or network reconnaissance. |
| **Risk Scoring** | **Weighted Alerts** | Adds **20pts** to score per event | Cumulative indicator of an active attack. |

    

🛠️ Prerequisites (Linux)

: To run this program, ensure you have the required libraries pre-loaaded in the Os: pip install streamlit pyshark plotly pandas requests.

Since this program relies on pyshark, (cmd line Wireshark network protocol sniffer) you must have TShark installed:

sudo apt update && sudo apt install tshark -y

to run from the cmd terminal:
sudo ~/enp1s0_env/bin/streamlit run network_guardian.py

*(defaults to Wired Eth0: ~/enp1s0 ) but once in the app, a drop down menu exists to use whatever network interface is available.  

