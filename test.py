from scapy.all import *

def print(packet):
    packet.show()

sniff(prn = print, count = 0)