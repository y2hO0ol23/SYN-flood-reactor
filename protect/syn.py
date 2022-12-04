from scapy.all import *
import imports
import os
import threading

from scapy.layers.inet import IP, TCP

global end, check

def handler(packet: Packet):
    global check

    ip, seq, sport, dport = packet[IP].src, packet[TCP].seq, packet[TCP].sport, packet[TCP].dport
    key = "%s:%d seq=%d"%(ip, sport, seq)
    
    if key not in check: check[key] = 0
    if not check[key]:
        cmd = "-s %s -d %s --protocol tcp --sport %d --dport %d --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, imports.ip, sport, dport)

        key[check] = 1
        os.system("iptables -I INPUT 1 %s"%cmd)
        
        while key[check] != 2: pass

        os.system("iptables -D INPUT %s"%cmd)
        key[check] = 0
    else:
        check[key] = 2


def init()->None:
    global end, check
    check = dict()
    end = False


def stop():
    global end
    end = True

filter = 'dst host %s and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == tcp-syn'%imports.ip