import scapy.all as scapy
import time
import sys
import os
from datetime import datetime
import platform
from tabulate import tabulate

class NetworkPacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.filter_type = None
        self.interface = None
        # ANSI color codes
        self.COLOR_PURPLE = '\033[95m'
        self.COLOR_PINK = '\033[91m'
        self.COLOR_BRIGHT_GREEN = '\033[92m'
        self.COLOR_BRIGHT_YELLOW = '\033[93m'
        self.COLOR_BRIGHT_BLUE = '\033[94m'
        self.COLOR_BRIGHT_CYAN = '\033[96m'
        self.COLOR_CYAN = '\033[36m'
        self.COLOR_RED = '\033[31m'
        self.COLOR_RESET = '\033[0m'
        # Check if IGMP is available in scapy
        self.has_igmp = False
        try:
            scapy.IGMP
            self.has_igmp = True
        except AttributeError:
            print(f"{self.COLOR_BRIGHT_YELLOW}Warning: IGMP layer not available in this version of Scapy. IGMP packets will be treated as 'Other'.{self.COLOR_RESET}")

    def display_banner(self):
        neon_colors = [self.COLOR_PURPLE, self.COLOR_PINK, self.COLOR_BRIGHT_GREEN, 
                       self.COLOR_BRIGHT_YELLOW, self.COLOR_BRIGHT_BLUE, self.COLOR_BRIGHT_CYAN]

        # Banner
        banner_lines = [
            f"{neon_colors[0]}   ███╗   ██╗███████╗████████╗    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗{self.COLOR_RESET}",
            f"{neon_colors[1]}   ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝{self.COLOR_RESET}",
            f"{neon_colors[2]}   ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║██║     █████╔╝ █████╗     ██║   {self.COLOR_RESET}",
            f"{neon_colors[3]}   ██║╚██╗██║██╔══╝     ██║       ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   {self.COLOR_RESET}",
            f"{neon_colors[5]}   ██║ ╚████║███████╗   ██║       ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║    {self.COLOR_RESET}",
            f"{neon_colors[4]}  Network Packet Analyzer v1.0{self.COLOR_RESET}"
        ]

        try:
            # Line-by-line animation effect
            for line in banner_lines:
                sys.stdout.write(line + '\n')
                sys.stdout.flush()
                time.sleep(0.2)  # Delay between lines
            print()

            # Display developer credit
            print(f"{self.COLOR_CYAN}{'─' * 30}{self.COLOR_RESET}")
            print(f"{self.COLOR_BRIGHT_YELLOW}  Developed by Ashok (NeospectraX){self.COLOR_RESET}")
            print(f"{self.COLOR_CYAN}{'─' * 30}{self.COLOR_RESET}\n")
        except KeyboardInterrupt:
            # In case user interrupts the banner animation
            print(f"\n{self.COLOR_BRIGHT_CYAN}Banner display interrupted. Moving on...{self.COLOR_RESET}")

    def safe_input(self, prompt):
        """Handle keyboard interrupts during input calls"""
        try:
            return input(prompt).strip()
        except KeyboardInterrupt:
            print(f"\n{self.COLOR_BRIGHT_CYAN}Operation cancelled by user.{self.COLOR_RESET}")
            return ""
        except Exception as e:
            print(f"{self.COLOR_RED}Input error: {str(e)}{self.COLOR_RESET}")
            return ""

    def display_menu(self):
        menu = f"""
{self.COLOR_BRIGHT_CYAN}Network Packet Analyzer Menu:{self.COLOR_RESET}
1. List Interfaces
2. Start Capture
3. Filter Packets
4. Show Packet Details
5. Show Statistics
6. Save Capture
7. Exit

{self.COLOR_BRIGHT_YELLOW}Select an option:{self.COLOR_RESET} """
        return self.safe_input(menu)

    def list_interfaces(self):
        print(f"{self.COLOR_BRIGHT_GREEN}Available Interfaces:{self.COLOR_RESET}")
        try:
            if platform.system() == "Windows":
                # Get raw interface list from scapy
                raw_interfaces = scapy.get_if_list()
                if not raw_interfaces:
                    print(f"{self.COLOR_RED}No interfaces found. Ensure Npcap is installed and you have network interfaces configured.{self.COLOR_RESET}")
                    return

                # Use conf.ifaces to get detailed interface info
                from scapy.config import conf
                iface_dict = {}
                try:
                    # Iterate over conf.ifaces to get objects
                    for iface_name in raw_interfaces:
                        if iface_name in conf.ifaces:
                            iface_obj = conf.ifaces[iface_name]
                            friendly_name = getattr(iface_obj, 'description', iface_name)
                            npf_name = iface_name
                            iface_dict[npf_name] = friendly_name
                except Exception as e:
                    print(f"{self.COLOR_BRIGHT_YELLOW}Warning: Could not fetch friendly names: {e}{self.COLOR_RESET}")

                # Display interfaces with friendly names if available
                table_data = []
                for npf_name in raw_interfaces:
                    friendly_name = iface_dict.get(npf_name, npf_name)
                    table_data.append([friendly_name, npf_name])
                print(tabulate(table_data, headers=["Friendly Name", "Interface Name"], tablefmt="grid"))
            else:
                # On Linux/macOS, use get_if_list
                interfaces = scapy.get_if_list()
                if not interfaces:
                    print(f"{self.COLOR_RED}No interfaces found. Ensure you have network interfaces configured.{self.COLOR_RESET}")
                else:
                    table_data = [[iface] for iface in interfaces]
                    print(tabulate(table_data, headers=["Interface Name"], tablefmt="grid"))
        except Exception as e:
            print(f"{self.COLOR_RED}Error fetching interfaces: {e}{self.COLOR_RESET}")
            print(f"{self.COLOR_BRIGHT_YELLOW}Falling back to dummy list: eth0, wlan0{self.COLOR_RESET}")
            table_data = [["eth0"], ["wlan0"]]
            print(tabulate(table_data, headers=["Interface Name"], tablefmt="grid"))

    def start_capture(self):
        if not self.interface:
            self.interface = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Enter interface (e.g., eth0 or Npcap name on Windows): {self.COLOR_RESET}")
            if not self.interface:
                print(f"{self.COLOR_RED}Error: Interface cannot be empty!{self.COLOR_RESET}")
                return
                
        # Get packet count or timeout
        try:
            packet_count = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Enter number of packets to capture (leave empty for unlimited): {self.COLOR_RESET}")
            packet_count = int(packet_count) if packet_count else 0
            
            timeout = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Enter capture timeout in seconds (leave empty for 60s): {self.COLOR_RESET}")
            timeout = int(timeout) if timeout else 60
        except ValueError:
            print(f"{self.COLOR_RED}Invalid number entered. Using defaults.{self.COLOR_RESET}")
            packet_count = 0
            timeout = 60
            
        print(f"{self.COLOR_BRIGHT_GREEN}Capturing on {self.interface} (Press Ctrl+C to stop)...{self.COLOR_RESET}")
        try:
            packet_filter = self.get_filter_expression()
            kwargs = {
                'iface': self.interface,
                'prn': self.packet_callback,
                'store': True,
                'timeout': timeout
            }
            if packet_count > 0:
                kwargs['count'] = packet_count
            if packet_filter:
                kwargs['filter'] = packet_filter
                
            scapy.sniff(**kwargs)
            print(f"\n{self.COLOR_BRIGHT_GREEN}Capture complete. {len(self.packets)} packets captured.{self.COLOR_RESET}")
        except KeyboardInterrupt:
            print(f"\n{self.COLOR_BRIGHT_CYAN}Capture stopped by user. {len(self.packets)} packets captured.{self.COLOR_RESET}")
        except (ValueError, AttributeError) as e:
            print(f"\n{self.COLOR_RED}Capture error: {e}{self.COLOR_RESET}")
        except Exception as e:
            print(f"\n{self.COLOR_RED}Unexpected error during capture: {e}{self.COLOR_RESET}")

    def get_filter_expression(self):
        """Convert our simple filter to a BPF filter expression for scapy.sniff"""
        if not self.filter_type:
            return ""
            
        if self.filter_type.lower() == "tcp":
            return "tcp"
        elif self.filter_type.lower() == "udp":
            return "udp"
        elif self.filter_type.lower() == "icmp":
            return "icmp"
        elif self.filter_type.startswith("ip "):
            ip = self.filter_type.split()[1]
            return f"host {ip}"
        return ""

    def packet_callback(self, packet):
        # Store the packet regardless of filter (we'll apply the filter in display)
        self.packets.append(packet)
        
        # Apply our display filter if needed
        if self.filter_type:
            if self.filter_type.lower() == "tcp" and not packet.haslayer(scapy.TCP):
                return
            elif self.filter_type.lower() == "udp" and not packet.haslayer(scapy.UDP):
                return
            elif self.filter_type.startswith("ip ") and packet.haslayer(scapy.IP):
                ip = self.filter_type.split()[1]
                if packet[scapy.IP].src != ip and packet[scapy.IP].dst != ip:
                    return

        packet_num = len(self.packets)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Initialize default values
        src_ip = dst_ip = "N/A"
        size = len(packet)
        ttl = "N/A"
        proto = "Unknown"
        port = "N/A"
        packet_type = "N/A"
        src_mac = dst_mac = "N/A"
        
        # Check for Ethernet layer
        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst
            
        # Check for IP layer
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            ttl = packet[scapy.IP].ttl
            
            # Check for specific protocols
            if packet.haslayer(scapy.TCP):
                proto = "TCP"
                port = packet[scapy.TCP].dport
                packet_type = f"Flags: {packet[scapy.TCP].flags}"
            elif packet.haslayer(scapy.UDP):
                proto = "UDP"
                port = packet[scapy.UDP].dport
            elif packet.haslayer(scapy.ICMP):
                proto = "ICMP"
                packet_type = f"Type: {packet[scapy.ICMP].type}"
            elif self.has_igmp and packet.haslayer(scapy.IGMP):
                proto = "IGMP"
                packet_type = f"Type: {packet[scapy.IGMP].type}"
            else:
                proto = "Other"
                
        # Display packet information in a table
        table_data = [[packet_num, timestamp, src_ip, dst_ip, proto, port, ttl, packet_type, src_mac, dst_mac, f"{size} bytes"]]
        try:
            print(tabulate(table_data, headers=["#", "Time", "Source IP", "Destination IP", "Protocol", 
                                               "Port", "TTL", "Packet Type", "Src MAC", "Dst MAC", "Size"], 
                           tablefmt="grid"))
        except Exception as e:
            print(f"{self.COLOR_RED}Error displaying packet: {e}{self.COLOR_RESET}")

    def filter_packets(self):
        print(f"{self.COLOR_BRIGHT_GREEN}Filter Options:{self.COLOR_RESET}")
        print("1. TCP packets only")
        print("2. UDP packets only")
        print("3. ICMP packets only")
        print("4. Filter by IP address")
        print("5. Clear filter")
        
        choice = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Enter option (1-5): {self.COLOR_RESET}")
        
        if choice == "1":
            self.filter_type = "tcp"
        elif choice == "2":
            self.filter_type = "udp"
        elif choice == "3":
            self.filter_type = "icmp"
        elif choice == "4":
            ip = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Enter IP address to filter: {self.COLOR_RESET}")
            if self.validate_ip(ip):
                self.filter_type = f"ip {ip}"
            else:
                print(f"{self.COLOR_RED}Invalid IP address. Filter not applied.{self.COLOR_RESET}")
                return
        elif choice == "5":
            self.filter_type = None
        else:
            print(f"{self.COLOR_RED}Invalid option. Filter not changed.{self.COLOR_RESET}")
            return
            
        print(f"{self.COLOR_BRIGHT_GREEN}Filter applied: {self.filter_type if self.filter_type else 'None'}{self.COLOR_RESET}")

    def validate_ip(self, ip):
        """Simple IP validation"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False
            for octet in octets:
                num = int(octet)
                if num < 0 or num > 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False

    def show_packet_details(self):
        if not self.packets:
            print(f"{self.COLOR_RED}No packets captured yet.{self.COLOR_RESET}")
            return
            
        try:
            packet_num = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Enter packet number (1-{len(self.packets)}): {self.COLOR_RESET}")
            if not packet_num:
                return
                
            packet_num = int(packet_num)
            if 1 <= packet_num <= len(self.packets):
                packet = self.packets[packet_num - 1]
                print(f"{self.COLOR_BRIGHT_GREEN}Packet {packet_num} Details:{self.COLOR_RESET}")
                
                table_data = []
                
                # Basic packet info
                table_data.append(["Size", f"{len(packet)} bytes"])
                table_data.append(["Time", datetime.now().strftime("%H:%M:%S")])
                
                # Layer information
                layers = self.get_packet_layers(packet)
                table_data.append(["Layers", ", ".join(layers)])
                
                # Ethernet layer
                if packet.haslayer(scapy.Ether):
                    table_data.append(["Source MAC", packet[scapy.Ether].src])
                    table_data.append(["Destination MAC", packet[scapy.Ether].dst])
                    table_data.append(["Ether Type", hex(packet[scapy.Ether].type)])
                
                # IP layer
                if packet.haslayer(scapy.IP):
                    table_data.append(["Source IP", packet[scapy.IP].src])
                    table_data.append(["Destination IP", packet[scapy.IP].dst])
                    table_data.append(["TTL", str(packet[scapy.IP].ttl)])
                    table_data.append(["IP Version", packet[scapy.IP].version])
                    table_data.append(["IP ID", packet[scapy.IP].id])
                    
                # TCP layer
                if packet.haslayer(scapy.TCP):
                    table_data.append(["Protocol", "TCP"])
                    table_data.append(["Source Port", str(packet[scapy.TCP].sport)])
                    table_data.append(["Destination Port", str(packet[scapy.TCP].dport)])
                    table_data.append(["TCP Flags", str(packet[scapy.TCP].flags)])
                    table_data.append(["Sequence", packet[scapy.TCP].seq])
                    table_data.append(["Acknowledgment", packet[scapy.TCP].ack])
                    table_data.append(["Window Size", packet[scapy.TCP].window])
                    
                # UDP layer
                elif packet.haslayer(scapy.UDP):
                    table_data.append(["Protocol", "UDP"])
                    table_data.append(["Source Port", str(packet[scapy.UDP].sport)])
                    table_data.append(["Destination Port", str(packet[scapy.UDP].dport)])
                    table_data.append(["Length", packet[scapy.UDP].len])
                    
                # ICMP layer
                elif packet.haslayer(scapy.ICMP):
                    table_data.append(["Protocol", "ICMP"])
                    table_data.append(["Type", str(packet[scapy.ICMP].type)])
                    table_data.append(["Code", str(packet[scapy.ICMP].code)])
                    
                # IGMP layer
                elif self.has_igmp and packet.haslayer(scapy.IGMP):
                    table_data.append(["Protocol", "IGMP"])
                    table_data.append(["Type", str(packet[scapy.IGMP].type)])
                
                print(tabulate(table_data, headers=["Field", "Value"], tablefmt="grid"))
                
                # Ask if user wants to see raw packet
                show_raw = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Show raw packet? (y/n): {self.COLOR_RESET}")
                if show_raw.lower() == 'y':
                    packet.show()
            else:
                print(f"{self.COLOR_RED}Invalid packet number. Must be between 1 and {len(self.packets)}.{self.COLOR_RESET}")
        except ValueError:
            print(f"{self.COLOR_RED}Please enter a valid number.{self.COLOR_RESET}")
        except Exception as e:
            print(f"{self.COLOR_RED}Error displaying packet details: {e}{self.COLOR_RESET}")

    def get_packet_layers(self, packet):
        """Get all layers in a packet"""
        layers = []
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layers.append(layer.name)
            counter += 1
        return layers

    def show_stats(self):
        if not self.packets:
            print(f"{self.COLOR_RED}No packets captured yet.{self.COLOR_RESET}")
            return
            
        try:
            total = len(self.packets)
            tcp = len([p for p in self.packets if p.haslayer(scapy.TCP)])
            udp = len([p for p in self.packets if p.haslayer(scapy.UDP)])
            icmp = len([p for p in self.packets if p.haslayer(scapy.ICMP)])
            igmp = len([p for p in self.packets if self.has_igmp and p.haslayer(scapy.IGMP)])
            other = total - (tcp + udp + icmp + igmp)
            
            table_data = [
                ["Total Packets", total],
                ["TCP", tcp, f"{tcp/total*100:.1f}%" if total > 0 else "0%"],
                ["UDP", udp, f"{udp/total*100:.1f}%" if total > 0 else "0%"],
                ["ICMP", icmp, f"{icmp/total*100:.1f}%" if total > 0 else "0%"],
                ["IGMP", igmp, f"{igmp/total*100:.1f}%" if total > 0 else "0%"],
                ["Other", other, f"{other/total*100:.1f}%" if total > 0 else "0%"]
            ]
            
            print(f"{self.COLOR_BRIGHT_GREEN}Packet Statistics:{self.COLOR_RESET}")
            print(tabulate(table_data, headers=["Protocol", "Count", "Percentage"], tablefmt="grid"))
            
            # IP statistics
            ip_packets = [p for p in self.packets if p.haslayer(scapy.IP)]
            if ip_packets:
                ip_src = {}
                ip_dst = {}
                
                for p in ip_packets:
                    src = p[scapy.IP].src
                    dst = p[scapy.IP].dst
                    
                    ip_src[src] = ip_src.get(src, 0) + 1
                    ip_dst[dst] = ip_dst.get(dst, 0) + 1
                
                print(f"\n{self.COLOR_BRIGHT_GREEN}Top Source IP Addresses:{self.COLOR_RESET}")
                src_table = [[ip, count, f"{count/len(ip_packets)*100:.1f}%"] 
                             for ip, count in sorted(ip_src.items(), key=lambda x: x[1], reverse=True)[:5]]
                print(tabulate(src_table, headers=["Source IP", "Count", "Percentage"], tablefmt="grid"))
                
                print(f"\n{self.COLOR_BRIGHT_GREEN}Top Destination IP Addresses:{self.COLOR_RESET}")
                dst_table = [[ip, count, f"{count/len(ip_packets)*100:.1f}%"] 
                             for ip, count in sorted(ip_dst.items(), key=lambda x: x[1], reverse=True)[:5]]
                print(tabulate(dst_table, headers=["Destination IP", "Count", "Percentage"], tablefmt="grid"))
        except Exception as e:
            print(f"{self.COLOR_RED}Error computing statistics: {e}{self.COLOR_RESET}")

    def save_capture(self):
        if not self.packets:
            print(f"{self.COLOR_RED}No packets to save.{self.COLOR_RESET}")
            return
            
        try:
            # Create captures directory if it doesn't exist
            capture_dir = "captures"
            if not os.path.exists(capture_dir):
                os.makedirs(capture_dir)
                
            default_filename = f"{capture_dir}/capture_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
            filename = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Enter filename (default: {default_filename}): {self.COLOR_RESET}")
            filename = filename or default_filename
            
            if not filename.endswith('.pcap'):
                filename += '.pcap'
                
            scapy.wrpcap(filename, self.packets)
            print(f"{self.COLOR_BRIGHT_GREEN}Successfully saved {len(self.packets)} packets to {filename}{self.COLOR_RESET}")
            
            # Option to save summary report
            save_summary = self.safe_input(f"{self.COLOR_BRIGHT_CYAN}Save capture summary report? (y/n): {self.COLOR_RESET}")
            if save_summary.lower() == 'y':
                summary_file = filename.replace('.pcap', '_summary.txt')
                with open(summary_file, 'w') as f:
                    f.write(f"Network Packet Capture Summary\n")
                    f.write(f"==========================\n\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Interface: {self.interface}\n")
                    f.write(f"Filter: {self.filter_type if self.filter_type else 'None'}\n")
                    f.write(f"Total Packets: {len(self.packets)}\n\n")
                    
                    # Protocol breakdown
                    tcp = len([p for p in self.packets if p.haslayer(scapy.TCP)])
                    udp = len([p for p in self.packets if p.haslayer(scapy.UDP)])
                    icmp = len([p for p in self.packets if p.haslayer(scapy.ICMP)])
                    igmp = len([p for p in self.packets if self.has_igmp and p.haslayer(scapy.IGMP)])
                    other = len(self.packets) - (tcp + udp + icmp + igmp)
                    
                    f.write(f"Protocol Breakdown:\n")
                    f.write(f"  TCP: {tcp} ({tcp/len(self.packets)*100:.1f}%)\n")
                    f.write(f"  UDP: {udp} ({udp/len(self.packets)*100:.1f}%)\n")
                    f.write(f"  ICMP: {icmp} ({icmp/len(self.packets)*100:.1f}%)\n")
                    f.write(f"  IGMP: {igmp} ({igmp/len(self.packets)*100:.1f}%)\n")
                    f.write(f"  Other: {other} ({other/len(self.packets)*100:.1f}%)\n")
                
                print(f"{self.COLOR_BRIGHT_GREEN}Summary report saved to {summary_file}{self.COLOR_RESET}")
                
        except Exception as e:
            print(f"{self.COLOR_RED}Error saving capture: {e}{self.COLOR_RESET}")

    def run(self):
        try:
            self.display_banner()
            
            while True:
                choice = self.display_menu()
                if choice == "1":
                    self.list_interfaces()
                elif choice == "2":
                    self.start_capture()
                elif choice == "3":
                    self.filter_packets()
                elif choice == "4":
                    self.show_packet_details()
                elif choice == "5":
                    self.show_stats()
                elif choice == "6":
                    self.save_capture()
                elif choice == "7":
                    print(f"{self.COLOR_BRIGHT_CYAN}Goodbye!{self.COLOR_RESET}")
                    break
                else:
                    print(f"{self.COLOR_RED}Invalid option. Try again.{self.COLOR_RESET}")
        except KeyboardInterrupt:
            print(f"\n{self.COLOR_BRIGHT_CYAN}Program terminated by user. Goodbye!{self.COLOR_RESET}")
        except Exception as e:
            print(f"{self.COLOR_RED}Unexpected error: {str(e)}{self.COLOR_RESET}")
            
if __name__ == "__main__":
    analyzer = NetworkPacketAnalyzer()
    analyzer.run()
