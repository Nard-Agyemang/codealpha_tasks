import argparse
import sys
from scapy.all import sniff, IP, wrpcap, Raw

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Extracts and prints Source IP, Destination IP, Protocol, and Payload.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Map common protocol numbers to names
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = proto_map.get(proto, str(proto))
        
        print(f"[{protocol_name}] SRC: {src_ip} -> DST: {dst_ip}")
        
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                decoded_payload = payload.decode('utf-8')
                
                # Check if it's mostly printable
                if decoded_payload.isprintable():
                    # Preview the first 100 characters
                    preview = decoded_payload[:100]
                    if len(decoded_payload) > 100:
                        preview += "..."
                    print(f"   Payload Preview: {preview}")
                else:
                    # Mixed content (rare if decode succeeded but has control chars)
                    print(f"   Payload: [Binary Data - {len(payload)} bytes]\n\n")
                    
            except UnicodeDecodeError:
                # Decoded failed, so it's binary
                print(f"   Payload: [Binary Data - {len(packet[Raw].load)} bytes]\n\n")
            except Exception as e:
                 print(f"   Payload: [Error processing payload]")

def main():
    parser = argparse.ArgumentParser(description="Simple Network Packet Sniffer")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Interface to sniff on (default: scapy default)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file to save packets (e.g. captured.pcap)")
    args = parser.parse_args()

    print(f"Starting network sniffer...")
    if args.interface:
        print(f"Interface: {args.interface}")
    print(f"Packet Count: {'Infinite' if args.count == 0 else args.count}")
    if args.output:
        print(f"Saving packets to: {args.output}")
    print("Press Ctrl+C to stop.")

    try:
        # If output is specified, store is set to True (store=True) so we can save packets later.
        # Otherwise, store is set to False (store=False) to avoid consuming excessive memory during long runs.
        should_store = bool(args.output)
        captured_packets = sniff(prn=packet_callback, count=args.count, store=should_store, iface=args.interface)
        
        if args.output and captured_packets:
            print(f"\nSaving {len(captured_packets)} packets to {args.output}...")
            wrpcap(args.output, captured_packets)
            print("Done.")

    except KeyboardInterrupt:
        print("\nStopping sniffer.")
        # If storing and user hit Ctrl+C, sniff returns what it caught so far.
        # But there is the need to handle the variable scope if sniff was interrupted. 
        # Scapy sniff returns the list even on KeyboardInterrupt if store=True.
        # However, in the try block, the return value assignment might be skipped if exception happens *inside* sniff?
        
    except PermissionError:
        print("\nError: Permission denied. You may need to run this script as an administrator/root.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    main()
