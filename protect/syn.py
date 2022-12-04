from scapy.all import *
import time as tm
import imports
import utils
import os
import threading

from scapy.layers.inet import IP, TCP

global end, check, queue

def slave(data: tuple, time:float):
    global check, queue
    ip, seq, sport, dport = data
    key = "%s %d"%(ip, sport)

    if key in check: return

    syn_ack = IP(src=imports.ip, dst=ip)/TCP(sport=dport, dport=sport, flags='SA', ack=seq+1)
    for _ in range(3):
        send(syn_ack, verbose=False)
    
    syn = IP(src=ip, dst=imports.ip)/TCP(sport=sport, dport=dport, flags='S', seq=seq)
    pkt = sr1(syn, timeout=imports.timeout, verbose=False)
    if pkt != None:
        queue.append((ip, sport, dport, syn))
    
    check[key] = False


def master(time:float)->None:
    global end

    directory = './log/' + imports.syn_dir + '/'
    list1 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 2 - imports.delay))
    list2 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 1 - imports.delay))
    
    list1 = utils.read(list1, str, int, int, int)
    list2 = utils.read(list2, str, int, int, int)

    threads = []
    for data in list1 + list2:
        threads.append(threading.Thread(target = slave, args = (data, time), daemon=True))
    
    for thread in threads:
        thread.start()
    
    while not end: pass


def queue_handler():
    global end, queue

    def retry(ip, sport, dport, syn):
        cmd = "-s %s --sport %s -d %d --dport %s --protocol tcp --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, sport, imports.ip, dport)
        os.system("iptables -I INPUT 1 %s"%cmd)
        sr1(syn, verbose=False, timeout=imports.timeout)
        os.system("iptables -D INPUT %s"%cmd)

    while not end:
        if len(queue) > 0:
            ip, sport, dport, syn = queue[0]
            thread = threading.Thread(target=retry, args=(ip, sport, dport, syn))
            thread.start()
            print(ip)

        queue = queue[1:]


def run(time:float)->threading.Thread:
    global end, check, queue

    end = False
    check = dict()
    queue = []

    threads = (
        threading.Thread(target=master, args=(time, )),
        threading.Thread(target=queue_handler)
    )
    for thread in threads:
        thread.start()

def stop():
    global end
    end = True
