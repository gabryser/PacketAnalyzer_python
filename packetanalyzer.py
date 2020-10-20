#!/usr/bin/env python
import scapy.all as scapy
import argparse
from logger import *
import os

synIpDictonary = {}
boundary = 3 #minimum SYN request without ACK response to signal a syn flood


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    ipSrc = packet.sprintf('%IP.src%')
    ipDst = packet.sprintf('%IP.dst%')
    Protocol = packet.sprintf('%IP.proto%')
    #create the log
    create_log(ipSrc, ipDst, Protocol)



#istruction for UDP packets
    if packet.haslayer(scapy.UDP):
        UDP_Dport = packet.sprintf('%UDP.dport%')
        UDP_Sport= packet.sprintf('%UDP.sport%')
        udp_logger(UDP_Sport, UDP_Dport)


#instruction for ICMP packets
    if packet.haslayer(scapy.ICMP):
        IcmpType = packet.sprintf('%ICMP.type%')
        IcmpCode = packet.sprintf('%ICMP.code%')
        IcmpChecksum = packet.sprintf('%ICMP.chksum%')
        icmp_logger(IcmpType, IcmpCode, IcmpChecksum)


#istruction for TCP packet (execute synflood_checker)
    if packet.haslayer(scapy.TCP):
        flagsTCP = packet.sprintf('%TCP.flags%')
        TCP_Dport = packet.sprintf('%TCP.dport%')
        TCP_Sport = packet.sprintf('%TCP.sport%')
        synflood_checker(ipSrc, flagsTCP)
        tcp_logger(flagsTCP, TCP_Sport, TCP_Dport)



   # print("\nSourceIP: " + ipSrc + "\tDestinationIP: " + ipDst + "\tProtocol: " + Protocol)


# function to detect a probably Synflood, add 1 to counter when receive a SYN and remove 1 when receive an ACK as response
def synflood_checker(ipSrc, flagsTCP):
    if flagsTCP == 'S':
        if ipSrc in synIpDictonary:
            synIpDictonary[ipSrc] += 1
        else:
            synIpDictonary[ipSrc] = 1
        #print('IP source: ' + ipSrc + ' TCP flags:' + flagsTCP)

    if ipSrc in synIpDictonary and flagsTCP == 'A':
        synIpDictonary[ipSrc] -= 1

#report an IP if sends a lot of SYN request without receiving ACK as response
    if ipSrc in synIpDictonary and synIpDictonary[ipSrc] > boundary:
        synflood_log(ipSrc)
       # print('Flood of SYN pack received from the IP: ' + ipSrc)

#choose which interface have to sniff
def sniffing():
    listInterface = os.listdir('/sys/class/net')
    i = 0
    print('Select interface:\n')
    for iface in listInterface:
        print("Press " + str(i) + " for interface " + iface + '\n')
        i +=1
    selection =-1
    while len(listInterface) <= selection or selection < 0:
        selection = int(input())

    #insrt selcted interface in this variable, then star sniffing it
    ifaceSelected = listInterface[selection]
    log_reset()
    sniff(ifaceSelected)