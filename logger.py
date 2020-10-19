
import logging
import time

def create_log(ipSrc, ipDst, Protocol):
    log = open('Analysis_log.txt', 'a')
    log.write("\n" + time.strftime("%H:%M:%S"))
    log.write("\nSource IP: " + str(ipSrc) + "\tDestination IP: " + str(ipDst) + "\tProtocol: " + str(Protocol))
    print(ipSrc)


def synfloodflood_log():
    log = open('SYN_Flood_log', 'a')
    log.write("\n" + time.strftime("%H:%M:%S"))
    log.write("Suspect SYN Flood attack detected!")