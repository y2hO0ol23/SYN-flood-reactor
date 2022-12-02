from scapy.all import *
import utils as utils
import time as tm
import imports

def drop_syn_init(packet:Packet)->None:
    print(packet.seq)


def drop_syn(packet:Packet)->None:
    pass

def master(time:float)->None:
    global end

    directory = './log/' + imports.syn_dir + '/'
    list1 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 2 - imports.delay))
    list2 = directory + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(time - 1 - imports.delay))
    
    list1 = utils.read(list1)
    list2 = utils.read(list2)

    check = dict()

    slaves = []
    for ip in list1 + list2:
        if ip not in check:
            print(imports.syn_drop_filter%(imports.ip,ip))
            slave = threading.Thread(target = sniff, kwargs={"prn" : drop_syn_init, "count" : 1, "filter" : imports.syn_drop_filter%(imports.ip,ip)}, daemon=True)
            slave.run()
            check[ip] = time
    
    while not end: pass

global end
def run(time:float)->tuple:
    global end
    end = False
    master = threading.Thread(target = master, args = (time))
    master.run()

def stop():
    global end
    end = True
