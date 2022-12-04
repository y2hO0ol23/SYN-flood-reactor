import os, atexit, threading
from scapy.all import *

import imports
from protect.all import *

drop_all_syn = '-d %s --protocol tcp --tcp-flags SYN,RST,ACK,FIN SYN -j DROP'%imports.ip

def add_chain():
    os.system('iptables -I INPUT 1 %s'%drop_all_syn)

def remove_chain():
    os.system('iptables -D INPUT %s'%drop_all_syn)


def main():
    protect.syn.init()
    atexit.register(protect.syn.stop)

    threads = [
        threading.Thread(target=sniff, kwargs={"prn" : protect.syn.handler, "count" : 0, "filter" : protect.syn.filter}, daemon=True)
    ]

    for thread in threads:
        thread.start()


if __name__ == '__main__':  
    add_chain()
    atexit.register(remove_chain)

    main()

    try:
        open('rmToStop','w')
        while True:
            if not os.path.isfile('rmToStop'):
                break
    except KeyboardInterrupt:
        sys.exit()
