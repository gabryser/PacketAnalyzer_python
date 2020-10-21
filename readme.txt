My Packet Analyzer detect SYN Flood attacks and pinpoint an attacker when he try to perform an ARP spoofing attack.

This program run with Python 3.8 interpreter.
You also need to install the following python package:
pip
scapy
how to install scapy on linux:
https://scapy.readthedocs.io/en/latest/installation.html

my project is on github: 
https://github.com/gabryser/PacketAnalyzer_python

DESCRIPTION:
packetanalyzer.py contains instructions to analyze packet and detect attack:
For SYNFlood attack launch a warning if receive a lot of SYN request without correspondand ACK response
For pinpoint attacker IP, system get the MAC address to which he sent ARP request and compare to MAC adder from which he receive the response; if it doesn't match he launch and warning and log the mac and the ip address of the host who sent the response.
logger.py contains instruction for logging (2 different logs: lists of packet and attack warnings)
main.py to execute sniffing
ARPSpoofingAttack.py script to perform Arp spoofing attack
SYNFloodAttack.py script to perform a SYN flood attack


