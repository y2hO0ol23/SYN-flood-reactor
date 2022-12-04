from scapy.all import *
import imports
import os
import threading

from scapy.layers.inet import IP, TCP

global end, queue

def handler(packet: Packet):
    global check, queue
    ip, seq, sport, dport = packet[IP].src, packet[TCP].seq, packet[TCP].sport, packet[TCP].dport
    key = "%s %d %d"%(ip, sport, seq)

    if key in check:
        queue.append((ip, seq ,sport, dport))
    
    check[key] = True


def queue_handler():
    global end, queue

    def retry(ip, seq, sport, dport):
        cmd = "-s %s -d %s --protocol tcp --sport %d --dport %d --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, imports.ip, sport, dport)
        os.system("iptables -I INPUT 1 %s"%cmd)
        
        syn = IP(src=ip, dst=imports.ip)/TCP(sport=sport, dport=dport, flags='S', seq=seq)
        sr1(syn, verbose=False, timeout=imports.timeout)

        key = "%s %d %d"%(ip, sport, seq)
        del check[key]
        
        os.system("iptables -D INPUT %s"%cmd)

    while not end:
        if len(queue) > 0:
            ip, seq, sport, dport = queue[0]
            thread = threading.Thread(target=retry, args=(ip, seq, sport, dport))
            thread.start()
            print(ip)

        queue = queue[1:]


def init()->None:
    global end, check, queue

    end = False
    check = dict()
    queue = []

    threading.Thread(target=queue_handler).start()

def stop():
    global end
    end = True

filter = 'dst host %s and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == tcp-syn'%imports.ip