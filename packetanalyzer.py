#!/usr/bin/python
import scapy.all as scapy
import os
from logger import *
synIpDictonary = {}
boundary = 3  # minimum SYN request without ACK response to signal a syn flood


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)


def get_mac(ip):
    """
    Returns the MAC address of `ip`, if it is unable to find it
    for some reason, throws `IndexError`
    """
    p = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.ARP(pdst=ip)
    result = scapy.srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc


def process_packet(packet):
    ipSrc = packet.sprintf('%IP.src%')
    ipDst = packet.sprintf('%IP.dst%')
    Protocol = packet.sprintf('%IP.proto%')
    create_log(ipSrc, ipDst, Protocol)   # create the log


# istruction for UDP packets
    if packet.haslayer(scapy.UDP):
        UDP_Dport = packet.sprintf('%UDP.dport%')
        UDP_Sport= packet.sprintf('%UDP.sport%')
        udp_logger(UDP_Sport, UDP_Dport)


# instruction for ICMP packets
    if packet.haslayer(scapy.ICMP):
        IcmpType = packet.sprintf('%ICMP.type%')
        IcmpCode = packet.sprintf('%ICMP.code%')
        IcmpChecksum = packet.sprintf('%ICMP.chksum%')
        icmp_logger(IcmpType, IcmpCode, IcmpChecksum)


# istruction for TCP packet (execute synflood_checker)
    if packet.haslayer(scapy.TCP):
        flagsTCP = packet.sprintf('%TCP.flags%')
        TCP_Dport = packet.sprintf('%TCP.dport%')
        TCP_Sport = packet.sprintf('%TCP.sport%')
        synflood_checker(ipSrc, flagsTCP)
        tcp_logger(flagsTCP, TCP_Sport, TCP_Dport)


# if the packet is an ARP packet
    if packet.haslayer(scapy.ARP):
        # if it is an ARP response (ARP reply)
        if packet[scapy.ARP].op == 2:
            try:
                # get the real MAC address of the sender
                real_mac = get_mac(packet[scapy.ARP].psrc)
                # get the MAC address from the packet sent to us
                response_mac = packet[scapy.ARP].hwsrc
                # if they're different, definetely there is an attack
                if real_mac != response_mac:
                    ip_attacker = packet.sprintf('%IP.src%')
                    arp_spoofing_author(ip_attacker)
                   # print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
            except IndexError:
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass


# print("\nSourceIP: " + ipSrc + "\tDestinationIP: " + ipDst + "\tProtocol: " + Protocol)

# to detect a probably Synflood, add 1 to counter when receive a SYN and remove 1 when receive an ACK as response
def synflood_checker(ipSrc, flagsTCP):
    if flagsTCP == 'S':
        if ipSrc in synIpDictonary:
            synIpDictonary[ipSrc] += 1
        else:
            synIpDictonary[ipSrc] = 1

    if ipSrc in synIpDictonary and flagsTCP == 'A':
        synIpDictonary[ipSrc] -= 1

# report an IP if sends a lot of SYN request without receiving ACK as response
    if ipSrc in synIpDictonary and synIpDictonary[ipSrc] > boundary:
        synflood_log(ipSrc)


# choose which interface have to sniff
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

    # insrt selcted interface in this variable, then star sniffing it
    ifaceSelected = listInterface[selection]
    log_reset()
    sniff(ifaceSelected)
