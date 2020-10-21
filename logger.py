
import time

def log_reset():
    open('Analysis_log.txt', 'w').close()
    open('SYN_Flood_log.txt', 'w').close()
    log = open('Analysis_log.txt', 'a')
    log.write("\nNetwork Scan Date: " + time.strftime("%m/%d/%Y"))

def create_log(ipSrc, ipDst, Protocol):
    log = open('Analysis_log.txt', 'a')
    log.write('\n_____________________________________________________________________________________________')
    log.write("\n" + time.strftime("%H:%M:%S"))
    log.write("\nSource IP: " + str(ipSrc) + "\tDestination IP: " + str(ipDst) + "\tProtocol: " + str(Protocol))


def tcp_logger(flagsTCP, TCP_Sport, TCP_Dport):
    log = open('Analysis_log.txt', 'a')
    log.write("\nTCP segment. Flags: " + str(flagsTCP) + "\tSource Port: " +(TCP_Sport) + "\tDestination Port: " + str(TCP_Dport))



def udp_logger(UDP_Sport, UDP_Dport):
    log = open('Analysis_log.txt', 'a')
    log.write("\nUDP segment. Source Port: " +(UDP_Sport) + "\tDestination Port: " + str(UDP_Dport))



def icmp_logger(type, code, checksum):
    log = open('Analysis_log.txt', 'a')
    log.write("\nICMP packet. Type: " + str(type) + "\tCode: " +(code) + "\tchecksum: " + str(checksum))



def synflood_log(attackIP):
    log = open('Attack_log', 'a')
    log.write('\n_____________________________________________________________________________________________')
    log.write("\n" + time.strftime("%m/%d/%Y, %H:%M:%S"))
    log.write("Suspect SYN Flood attack detected!")
    log.write('The attack come from this suspected IP address: '+str(attackIP))


def arp_spoofing_author(attackIP):
    log = open('Attack_log', 'a')
    log.write('\n_____________________________________________________________________________________________')
    log.write("\n" + time.strftime("%m/%d/%Y, %H:%M:%S"))
    log.write("Suspect ARP Spoofing attack detected!")
    log.write('The attack come from this suspected IP address: '+str(attackIP))




