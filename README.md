# 🌐 Network Packet Analyzer

A Python-based CLI tool for capturing, analyzing, and filtering network packets using Scapy. Features a neon-colored interface, packet statistics, and the ability to save captures in `.pcap` format. Ideal for network enthusiasts and security researchers.

---

## 🔥 Features
✅ **List Network Interfaces:** Supports Windows, Linux, and macOS  
✅ **Packet Capture:** Capture packets with customizable count and timeout  
✅ **Filter Packets:** Filter by protocol (TCP, UDP, ICMP) or IP address  
✅ **Detailed Packet Info:** Displays IP, MAC, ports, TTL, etc.  
✅ **Packet Statistics:** Protocol breakdown and top IP analysis  
✅ **Save Captures:** Export captured packets to `.pcap` files with optional summary reports  
✅ **Interactive Menu:** Features a vibrant ANSI-colored output for better visibility  
✅ **Cross-Platform Support:** Requires Npcap for Windows compatibility  

---

## 📋 Prerequisites
- Python 3.8 or higher  
- **Windows:** Install [Npcap](https://npcap.com/#download) for packet capturing  
- **Linux:** Run with `sudo` for interface access  
- A network interface with active traffic  

---

## 💻 Installation

1. **Clone the Repository:**
```bash
git clone https://github.com/NeospectraX/PRODIGY_CS_05.git
cd network-packet-analyzer
```

2. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the Tool:**
```bash
python network_packet_analyzer.py
```
On Linux, use `sudo`:
```bash
sudo python network_packet_analyzer.py
```

---

## 🚀 Usage

1. **Launch the Tool:**
```bash
python network_packet_analyzer.py
```

2. **Menu Options:**
- `1. List Interfaces`: Show available network interfaces  
- `2. Start Capture`: Begin packet capturing  
- `3. Filter Packets`: Filter by TCP, UDP, ICMP, or IP  
- `4. Show Packet Details`: View detailed info of a specific packet  
- `5. Show Statistics`: Display protocol and IP stats  
- `6. Save Capture`: Save packets to a `.pcap` file  
- `7. Exit`: Quit the program  

3. **Example:**
- Start capturing:
```
Select an option: 2
Enter interface: eth0
Enter number of packets to capture: 100
Enter capture timeout in seconds: 30
```
Output will show a live table of captured packets.

- Filter TCP packets:
```
Select an option: 3
Enter option: 1
Filter applied: tcp
```

- Save capture:
```
Select an option: 6
Enter filename: captures/mycapture.pcap
Save capture summary report? (y/n): y
```

---

## 🧩 How It Works
- **Packet Capture:** Uses Scapy’s `sniff` function to capture packets on a specified interface.  
- **Filtering:** Supports real-time filtering by protocol or IP address.  
- **Analysis:** Displays packet details (e.g., MAC, IP, ports) and computes stats.  
- **Output:** Saves packets in `.pcap` format, compatible with Wireshark.  

---

## ❗ Important Notes
✅ **Permissions:** On Linux/macOS, root privileges may be required (`sudo`).  
✅ **Windows:** Ensure Npcap is installed and interface names match Npcap naming (e.g., `\Device\NPF_{GUID}`).  
✅ **IGMP Support:** Some Scapy versions may not support IGMP; such packets will be labeled "Other".  
✅ **Interrupt:** Press `Ctrl+C` to stop capturing or exit the program.  

---

## 📊 Sample Output
```
# | Time     | Source IP    | Destination IP | Protocol | Port | TTL | Packet Type | Src MAC         | Dst MAC         | Size
--|----------|--------------|----------------|----------|------|-----|-------------|-----------------|-----------------|------
1 | 14:30:25 | 192.168.1.10 | 8.8.8.8        | TCP      | 80   | 64  | Flags: S    | 00:14:22:01:23:45 | ff:ff:ff:ff:ff:ff | 54 bytes
```

---

## 🛠️ Troubleshooting
- **No interfaces found:** Check Npcap installation (Windows) or permissions (Linux).  
- **Capture fails:** Verify the interface name and ensure it’s active.  
- **Slow performance:** Reduce packet count or timeout for large networks.  

---

## 📝 License
This project is licensed under the **MIT License**.

💬 _Developed by Ashok (Nickname: NeospectraX). Contributions are welcome!_

