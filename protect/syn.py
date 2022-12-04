from scapy.all import *
import imports
import os
import threading
from time import sleep

from scapy.layers.inet import IP, TCP

global end, check

def timeout(key, chk):
    global check
    sleep(imports.timeout)
    if not chk.end:
        check[key] = 3

class timeout_chk():
    def __init__(self):
        self.end = False

def handler(packet: Packet):
    ip, seq, sport, dport = packet[IP].src, packet[TCP].seq, packet[TCP].sport, packet[TCP].dport
    threading.Thread(target=run, args=(ip, seq, sport, dport)).start()

def run(ip:str, seq:int, sport:int, dport:int):
    global check

    key = "%s:%d seq=%d"%(ip, sport, seq)
    
    if key not in check: check[key] = 0
    if not check[key]:
        check[key] = 1
        
        chk = timeout_chk()
        threading.Thread(target=timeout, args=(key, chk)).start()
        while check[key] != 2: pass
        chk.end = True

        if check[key] == 2:
            cmd = "-s %s -d %s --protocol tcp --sport %d --dport %d --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, imports.ip, sport, dport)

            os.system("iptables -I INPUT 1 %s"%cmd)
            
            send(IP(src=ip, dst=imports.ip)/TCP(seq=seq, sport=sport, dport=dport))

            sleep(0.5)
            os.system("iptables -D INPUT %s"%cmd)

        check[key] = 0
    else:
        print(key)
        check[key] = 2


def init()->None:
    global end, check
    check = dict()
    end = False


def stop():
    global end
    end = True

filter = 'dst host %s and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == tcp-syn'%imports.ip