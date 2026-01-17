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

on a modern Linux system (PEP 668), use the following to bypass environment restrictions or use a virtual environment:  source /home/guest/enp1s0_env/bin/activate
The instructions are mostly correct and functional, but they are a bit redundant and could be cleaned up to prevent user confusion. Specifically, you are installing some libraries twice (once via pip and once via apt), which can lead to version conflicts.


🛡️ How to Run Guardian HUD
1. Install System Dependencies

Before running the script, you must install TShark (the engine behind PyShark) and the Python development headers.
Bash

sudo apt update
sudo apt install tshark python3-pip -y

(When prompted, select Yes to allow non-superusers to capture packets.)
2. Prepare the Virtual Environment

Navigate to your environment and activate it. It is cleaner to install your libraries directly into the virtual environment rather than using sudo apt install python3-....
Bash

# Activate your environment
source ~/enp1s0_env/bin/activate

# Install Python libraries
pip install streamlit pyshark plotly pandas requests

3. Permissions Setup

Because pyshark needs to access your network interface directly, it usually requires root privileges. However, streamlit should ideally run from your environment's binary.

Run the app using this command:
Bash

sudo ~/enp1s0_env/bin/streamlit run ~/network_guardian.py

4. Access the HUD

Once started, the terminal will display your access URLs:


" You can now view your Streamlit app in your browser" e.g. :

  Local URL: http://localhost:8537
  Network URL: http://172.16.0.2:8537





