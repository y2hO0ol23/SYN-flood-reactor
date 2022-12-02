from scapy.all import *
import utils as utils
import time as tm
import imports

def drop_syn_init(packet:Packet)->None:
    print(packet.seq)


def drop_syn(packet:Packet)->None:
    pass

def slave(ip_list:set, time:float):
    global check

    for ip in set(ip_list):
        if ip not in check:
            print(imports.syn_drop_filter%(imports.ip,ip))
            init = threading.Thread(target = sniff, kwargs={"prn" : drop_syn_init, "count" : 1, "filter" : imports.syn_drop_filter%(imports.ip,ip)}, daemon=True)
            init.run()
            check[ip] = int(time)
    
    while True: pass

global end, check
def master(time:float)->None:
    global end

    directory = './log/' + imports.syn_dir + '/'
    list1 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 2 - imports.delay))
    list2 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 1 - imports.delay))
    
    list1 = utils.read(list1)
    list2 = utils.read(list2)

    slaveT = threading.Thread(target = slave, args = (set(list1 + list2), ), daemon=True)
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
