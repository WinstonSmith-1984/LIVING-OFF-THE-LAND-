# LOTL-LAN 🦀 (v1.9.57)

<p align="left">
  <a href="https://www.credly.com/badges/270c2310-e8c5-4216-b474-f24ff2d9cec4/public_url" target="_blank">
    <img src="https://images.credly.com/images/a74dc347-5429-4fc2-8878-74df7c213866/ibm-cybersecurity-analyst-professional-certificate.png" width="130" height="130" alt="IBM Cybersecurity Analyst Professional Certificate">
  </a>
</p>

**LOTL-LAN** is a tactical internal network monitoring and threat intelligence suite designed to detect **Living off the Land** (LOTL) attack vectors within a Local Area Network. By focusing on East-West traffic and protocol-specific anomalies (LLMNR, NBNS, MDNS, ARP), LOTL-LAN provides security analysts with real-time visibility into lateral movement and internal poisoning attempts.

---

## 🚀 Key Features

* **Active Threat Intelligence**: Automatically analyzes protocol frequency for lateral pivot patterns and escalates alerts to the System Security Status window.
* **East-West Threat Window**: A dedicated, scrollable log that deduplicates and tracks unique internal connection strings.
* **Protocol Decoder**: Deep-dive intelligence on discovery protocols used in NTLM relay and spoofing attacks.
* **Tactical HUD**: Includes a 5s stabilized refresh for zero-flicker UI, CSV export for forensic documentation, and a real-time Security Status Grid for ARP and scanning monitoring.

---

## 🛠️ Technical Requirements

### Dependencies & System Requirements
* **Python 3.9+**
* **Core Libraries**: Streamlit (HUD), PyShark (TShark wrapper), Plotly, and Pandas.
* **Host Requirements**: TShark (Wireshark) must be installed, and Root/Admin privileges are required for promiscuous mode packet capture.

---

## 📦 Installation & Usage

To deploy the suite, install the system-level packet capture tools, install the Python dependencies, and launch the application with administrative privileges:

```bash
sudo apt-get install tshark
pip install streamlit pyshark pandas plotly
streamlit run lotl_lan.py



📫 <a href="mailto:derekconlon&#64;hotmail&#46;co&#46;uk">Email me</a>


