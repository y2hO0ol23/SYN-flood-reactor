from scapy.all import *
import imports
import os
import threading

from scapy.layers.inet import IP, TCP

global end

def handler(packet: Packet):
    ip, seq, sport, dport = packet[IP].src, packet[TCP].seq, packet[TCP].sport, packet[TCP].dport

    cmd = "-s %s -d %s --protocol tcp --sport %d --dport %d --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, imports.ip, sport, dport)
    os.system("iptables -I INPUT 1 %s"%cmd)
    
    syn = IP(src=ip, dst=imports.ip)/TCP(sport=sport, dport=dport, flags='S', seq=seq)
    sr1(syn, verbose=False, timeout=imports.timeout)
    
    os.system("iptables -D INPUT %s"%cmd)


def init()->None:
    global end
    end = False


def stop():
    global end
    end = True

filter = 'dst host %s and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == tcp-syn'%imports.ip