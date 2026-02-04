import sys
import dpkt
import socket

def mac_addr(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)

def ip_addr(ip_bytes):
    return socket.inet_ntoa(ip_bytes)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    detected_syn_scanners = []
    detected_arp_spoofers = []

    # TODO: Declare any required data structures here
    # dict<str, int>
    ip_syn_sent_map = {}
    # dict<str, int>
    ip_syn_ack_rec_map = {}

    # dict<str, dict<str, int>>
    arp_requests_sent = {}
    arp_replies_received = {}

    #dict <str, int>
    unsolicited_replies = {}
    
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)

                    # TODO: Track SYN and SYN-ACK counts for each IP
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src_ip = ip_addr(ip.src)
                        dst_ip = ip_addr(ip.dst)
                        tcp = ip.data
                        flags = tcp.flags
                        if (flags & dpkt.tcp.TH_SYN) and not (flags & dpkt.tcp.TH_ACK):
                            ip_syn_sent_map[src_ip] = ip_syn_sent_map.get(src_ip, 0) + 1
                        elif (flags & dpkt.tcp.TH_SYN) and (flags & dpkt.tcp.TH_ACK):
                            ip_syn_ack_rec_map[dst_ip] = ip_syn_ack_rec_map.get(dst_ip, 0) + 1

                    # TODO: Count unsolicited ARP replies per MAC address
                    elif isinstance(eth.data, dpkt.arp.ARP):
                        arp = eth.data
                        sender_mac = mac_addr(arp.sha)
                        sender_ip = ip_addr(arp.spa)
                        target_ip = ip_addr(arp.tpa)
                        opcode = arp.op
                        if (opcode & dpkt.arp.ARP_OP_REQUEST): 
                            requests = arp_requests_sent.get(sender_ip, {})
                            requests[target_ip] = requests.get(target_ip, 0) + 1
                            arp_requests_sent[sender_ip] = requests
                        if (opcode & dpkt.arp.ARP_OP_REPLY):
                            replies = arp_replies_received.get(target_ip, {})
                            replies[sender_ip] = replies.get(sender_ip, 0) + 1
                            arp_replies_received[target_ip] = replies

                except Exception:
                    continue

    except Exception as e:
        print(f"Failed to process file: {e}")
        sys.exit(1)

    # TODO: Based on thresholds, add suspicious IPs/MACs to the result lists
    for src_ip, count in ip_syn_sent_map.items():
        if count > 5:
            # Check for 0 received or sent/received >= 3
            if ip_syn_ack_rec_map.get(src_ip, 0) == 0 or ip_syn_sent_map.get(src_ip) / ip_syn_ack_rec_map.get(src_ip) >= 3:
                detected_syn_scanners.append(src_ip)

    for target_ip, sender_map in arp_replies_received.items():
        for sender_ip, count in sender_map.items():
            if sender_ip not in arp_requests_sent.get(target_ip, {}):
                unsolicited_replies[sender_ip] = unsolicited_replies.get(sender_ip, 0) + count

    for sender_ip, count in unsolicited_replies.items():
        if count > 5:
            detected_arp_spoofers.append(sender_ip)

    print("Unauthorized SYN scanners:")
    for ip in sorted(detected_syn_scanners):
        print(ip)

    print("Unauthorized ARP spoofers:")
    for mac in sorted(detected_arp_spoofers):
        print(mac)

if __name__ == "__main__":
    main()
