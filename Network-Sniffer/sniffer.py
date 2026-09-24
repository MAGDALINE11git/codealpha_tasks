from scapy.all import (
    sniff,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ARP,
    Raw
)

from datetime import datetime


# ==========================================
# GLOBAL PACKET COUNTER
# ==========================================

packet_count = 0


# ==========================================
# PACKET ANALYZER
# ==========================================

def analyze_packet(packet):

    global packet_count

    packet_count += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    print("----------------------------------------")
    print(f"Packet #{packet_count}")
    print(f"Time            : {timestamp}")

    # ======================================
    # ARP
    # ======================================

    if ARP in packet:

        print("Packet Type     : ARP")

        print(f"Source MAC      : {packet[ARP].hwsrc}")
        print(f"Destination MAC : {packet[ARP].hwdst}")

        print(f"Source IP       : {packet[ARP].psrc}")
        print(f"Destination IP  : {packet[ARP].pdst}")

    # ======================================
    # IPv4
    # ======================================

    elif IP in packet:

        print("Packet Type     : IPv4")

        print(f"Source IP       : {packet[IP].src}")
        print(f"Destination IP  : {packet[IP].dst}")

        # ----------------------------------
        # TCP
        # ----------------------------------

        if TCP in packet:

            print("Transport       : TCP")

            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

            print(f"TCP Flags       : {packet[TCP].flags}")

            # HTTPS / TLS
            if (
                packet[TCP].sport == 443
                or packet[TCP].dport == 443
            ):

                print("Application     : HTTPS / TLS")

        # ----------------------------------
        # UDP
        # ----------------------------------

        elif UDP in packet:

            print("Transport       : UDP")

            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

            # DNS
            if (
                packet[UDP].sport == 53
                or packet[UDP].dport == 53
            ):

                print("Application     : DNS")

        # ----------------------------------
        # ICMP
        # ----------------------------------

        elif ICMP in packet:

            print("Transport       : ICMP")

            print("Application     : Network diagnostic")

        # ----------------------------------
        # Other IPv4 protocol
        # ----------------------------------

        else:

            print("Transport       : Other")

    # ======================================
    # IPv6
    # ======================================

    elif IPv6 in packet:

        print("Packet Type     : IPv6")

        print(f"Source IPv6     : {packet[IPv6].src}")
        print(f"Destination IPv6: {packet[IPv6].dst}")

        # ----------------------------------
        # TCP over IPv6
        # ----------------------------------

        if TCP in packet:

            print("Transport       : TCP")

            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

            print(f"TCP Flags       : {packet[TCP].flags}")

            if (
                packet[TCP].sport == 443
                or packet[TCP].dport == 443
            ):

                print("Application     : HTTPS / TLS")

        # ----------------------------------
        # UDP over IPv6
        # ----------------------------------

        elif UDP in packet:

            print("Transport       : UDP")

            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

            if (
                packet[UDP].sport == 53
                or packet[UDP].dport == 53
            ):

                print("Application     : DNS")

        # ----------------------------------
        # ICMPv6 Echo Request
        # ----------------------------------

        elif ICMPv6EchoRequest in packet:

            print("Transport       : ICMPv6")
            print("Message Type    : Echo Request")

        # ----------------------------------
        # ICMPv6 Echo Reply
        # ----------------------------------

        elif ICMPv6EchoReply in packet:

            print("Transport       : ICMPv6")
            print("Message Type    : Echo Reply")

        # ----------------------------------
        # Other IPv6 protocol
        # ----------------------------------

        else:

            print("Transport       : Other")

    # ======================================
    # OTHER PACKET
    # ======================================

    else:

        print("Packet Type     : Other")

    # ======================================
    # PACKET SIZE
    # ======================================

    print(f"Packet Size     : {len(packet)} bytes")

    # ======================================
    # RAW PAYLOAD
    # ======================================

    if Raw in packet:

        payload = bytes(packet[Raw].load)

        print(f"Payload Length  : {len(payload)} bytes")

        # Show only first 50 bytes
        print(f"Payload         : {payload[:50]}")

    else:

        print("Payload         : None")


# ==========================================
# FILTER MENU
# ==========================================

print("========================================")
print("          NETWORK SNIFFER")
print("========================================")

print()
print("Select packet filter:")
print()

print("1. All packets")
print("2. TCP")
print("3. UDP")
print("4. ICMP / ICMPv6")
print("5. HTTPS / TLS")
print("6. DNS")
print()

choice = input("Enter your choice (1-6): ").strip()


# ==========================================
# FILTER DEFINITIONS
# ==========================================

filters = {
    "1": None,
    "2": "tcp",
    "3": "udp",
    "4": "icmp or icmp6",
    "5": "tcp port 443",
    "6": "udp port 53"
}


# ==========================================
# VALIDATE CHOICE
# ==========================================

if choice not in filters:

    print("Invalid choice.")

    exit()


selected_filter = filters[choice]


# ==========================================
# START SNIFFER
# ==========================================

print()
print("========================================")
print("          STARTING SNIFFER")
print("========================================")

if selected_filter:

    print(f"Filter          : {selected_filter}")

else:

    print("Filter          : All packets")

print("Press CTRL+C to stop.")
print()


# ==========================================
# REAL-TIME CAPTURE
# ==========================================

try:

    sniff(
        filter=selected_filter,
        prn=analyze_packet,
        store=False
    )


except KeyboardInterrupt:

    print()
    print()
    print("========================================")
    print("          SNIFFER STOPPED")
    print("========================================")

    print(f"Total packets captured: {packet_count}")

    print("========================================")