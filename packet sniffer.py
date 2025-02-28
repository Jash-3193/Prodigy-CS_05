from scapy.all import sniff, get_if_list
import json
import os

# This function will be called for each captured packet
def packet_callback(packet):
    packet_info = {}

    try:
        if packet.haslayer('IP'):
            packet_info['src_ip'] = packet['IP'].src
            packet_info['dst_ip'] = packet['IP'].dst
            packet_info['protocol'] = packet['IP'].proto
            payload = str(packet.payload)
            packet_info['payload'] = payload[:100]  # Limit payload display to the first 100 characters

        elif packet.haslayer('ARP'):
            packet_info['src_ip'] = packet['ARP'].psrc
            packet_info['dst_ip'] = packet['ARP'].pdst
            packet_info['protocol'] = 'ARP'
            packet_info['payload'] = "ARP Request/Reply"

        # Convert to JSON for easy rendering in HTML
        packet_json = json.dumps(packet_info)
        
        # Check if the file exists, create it if not, and append data
        if not os.path.exists('packets.json'):
            with open('packets.json', 'w') as f:
                f.write('[]\n')  # Start with an empty JSON array to format the data correctly
        
        # Append the packet info to the JSON file
        with open('packets.json', 'a') as f:
            f.write(packet_json + "\n")
    
    except Exception as e:
        print(f"Error processing packet: {e}")

# Capture packets on the network, use prn to process each captured packet
def start_sniffing(interface=None):
    try:
        # Sniff packets (Scapy will automatically use Layer 3 for IP)
        print("Starting packet sniffer...")
        
        if interface:
            # Capture on a specific interface if given
            sniff(prn=packet_callback, store=0, iface=interface)
        else:
            # Capture on the default interface
            sniff(prn=packet_callback, store=0)
    except PermissionError:
        print("Error: Permission denied. Try running with elevated privileges (e.g., sudo).")
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")

if __name__ == "__main__":

    print("Available network interfaces:", get_if_list())
    
    interface = input("Enter the interface to capture packets on (or press Enter for default): ").strip()
    
    # Start sniffing on the specified interface or default
    start_sniffing(interface if interface else None)
