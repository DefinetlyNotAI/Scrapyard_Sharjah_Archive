from os import mkdir

from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

flag = "KEY{i_tES_TYU564678IUY^&*(I_E%$rf}"

# NOTICE
# The line in app.py is hardcoded as I couldn't find a way to dynamically get the correct line
# Rerunning this script will generate a new flag location, and so you must find the correct line again

if not os.path.exists("../assets/pcap"):
    mkdir("../assets/pcap")


def create_pcap(filename, range_sect, range_packets=750):
    packets = []
    flag_packet_index = random.randint(0, range_packets - 1)
    if range_sect == when:
        print(f"Flag will be included in packet {flag_packet_index + 1}")

    for i in range(range_packets):
        random_data = ''.join(random.choices("abcdef1234567890", k=29))
        load_data = flag if i == flag_packet_index and when == range_sect else random_data
        packetx = Ether() / IP(dst=f"192.168.1.{random.randint(1, 255)}") / TCP(dport=80) / Raw(load=load_data)
        packets.append(packetx)

    wrpcap(filename, packets)


when = random.randint(0, 100)
print(f"Flag will be included in file C4_{when}.pcap")
for j in range(100):
    create_pcap(f"assets/pcap/C4_{j}.pcap", j, range_packets=random.randint(500, 1000))
