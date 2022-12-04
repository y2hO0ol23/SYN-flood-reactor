from scapy.all import *
import utils as utils
import time as tm
import imports
import os

from scapy.layers.inet import IP, TCP

global check

def slave(data: tuple, time:float):
    global check
    ip, seq, sport, dport = data
    key = "%s %d"%(ip, sport)

    if key in check: return
    print(ip, seq, sport, dport)

    syn_ack = IP(src=imports.ip, dst=ip)/TCP(sport=dport, dport=sport, flags='SA', ack=seq+1)
    for _ in range(3):
        send(syn_ack, iface=False)
    
    syn = IP(src=ip, dst=imports.ip)/TCP(sport=sport, dport=dport, flags='S', seq=seq)
    pkt = sr1(syn, timeout=imports.timeout, iface=False)
    if pkt != None:
        cmd = "defence_syn_flood 1 -s %s --sport %s -d %d --dport %s --protocol tcp --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"%(ip, sport, imports.ip, dport)
        os.system("iptables -I "+cmd)
        send(syn)
        os.system("iptables -I "+cmd)

        print(ip,'=> accept')
    
    check[key] = False


global end
def master(time:float)->None:
    global end

    directory = './log/' + imports.syn_dir + '/'
    list1 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 2 - imports.delay))
    list2 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 1 - imports.delay))
    
    list1 = utils.read(list1, str, int, int, int)
    list2 = utils.read(list2, str, int, int, int)

    for data in list1 + list2:
        slaveT = threading.Thread(target = slave, args = (data, time), daemon=True)
        slaveT.run()
    
    while not end: pass

def run(time:float)->tuple:
    global end, check
    end = False
    check = dict()
    masterT = threading.Thread(target=master, args=(time, ))
    masterT.run()

def stop():
    global end
    end = True
