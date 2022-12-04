from scapy.all import *
import imports
import os
import threading
from time import sleep

from scapy.layers.inet import IP, TCP

global end, check

def timeout(key):
    sleep(imports.timeout)
    check[key] = 3

def handler(packet: Packet):
    global check

    ip, seq, sport, dport = packet[IP].src, packet[TCP].seq, packet[TCP].sport, packet[TCP].dport
    key = "%s:%d seq=%d"%(ip, sport, seq)
    
    if key not in check: check[key] = 0
    if not check[key]:
        check[key] = 1
        
        threading.Thread(target=timeout, args=(key, )).start()
        while check[key] < 2: pass
        
        if check[key] == 2:
            cmd = "-s %s -d %s --protocol tcp --sport %d --dport %d --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, imports.ip, sport, dport)

            os.system("iptables -I INPUT 1 %s"%cmd)

            sr1(IP(src=ip, dst=imports.ip)/TCP(seq=seq, sport=sport, dport=dport), timeout=imports.timeout)

            os.system("iptables -D INPUT %s"%cmd)

        check[key] = 0
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