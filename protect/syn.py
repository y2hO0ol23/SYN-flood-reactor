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

    if key not in check or not check[key]:
        cmd = "-s %s -d %s --protocol tcp --sport %d --dport %d --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, imports.ip, sport, dport)

        key[check] = True
        os.system("iptables -I INPUT 1 %s"%cmd)
        
        sniff(count=1, timeout=imports.timeout,
            filter='src host %s and dst host %s and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == tcp-syn and '%(ip, imports.ip) + \
                   'tcp.sport == %d and tcp.dport == %d and tcp.seq == %d'%(sport, dport, seq))

        os.system("iptables -D INPUT %s"%cmd)
        key[check] = False


def init()->None:
    global end, check
    check = dict()
    end = False


def stop():
    global end
    end = True

filter = 'dst host %s and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == tcp-syn'%imports.ip