for all those targeted individuals under repressive regimes -the "Winston smiths" ) a way to passively monitor their internet connection for signs of bad actor snooping, state or otherwise. 
Devlopd on Linux To run this, ensure you have the required libraries: pip install streamlit pyshark plotly pandas requests
Guardian HUD: Network Alert Status

A real-time network security monitoring dashboard built with Python, Streamlit, and PyShark. Designed for Linux users to visualize incoming traffic and detect potential threats.
🚀 Key Features

    Live Traffic Sniffing: Captures real-time packets using pyshark on specified interfaces.

    Risk Scoring System: Dynamically calculates threat levels based on TCP Reset flags and packet behavior.

    Geographic IP Mapping: Automatically resolves external IP addresses to physical locations (City/Country) and maps them in real-time.

    Visual Analytics: * Gauge Chart: Instant visualization of current risk levels.

        PPS History: Real-time graph showing "Packets Per Second" to detect spikes.

    WHOIS Intelligence: Displays ISP and Country data for incoming external traffic.

    Alerting System: Features a "Threat Log" and high-risk browser notifications (toasts).

🛠️ Prerequisites (Linux)

Since this uses pyshark, you must have TShark installed:
Bash

sudo apt update && sudo apt install tshark -y
