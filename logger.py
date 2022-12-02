from scapy.all import *
import threading
import os
import time as tm

class logger():
    def __init__(self, filter: str = ""):
        self.end = True
        self.filter = filter

    def log(self, filename:str, packet:scapy.packet)->None:
         while True:
            try:
                fd = open(filename, 'a+')
                fd.write(packet.show(dump=True))
                fd.close()
                break
            except:
                pass


    def manage(self, packet:scapy.packet)->None:
        filename = './log/' + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(tm.time()))
        thread = threading.Thread(target = self.log, args=(filename, packet))
        thread.start()
        

    def main(self)->None:
        slave = threading.Thread(target = sniff, kwargs={"prn" : self.manage, "count" : 0, "filter" : self.filter}, daemon=True)

        slave.start()
        while not self.end: pass

            
    def run(self)->None:
        self.end = False

        logger = threading.Thread(target = self.main)
        logger.start()


    def stop(self)->None:
        self.end = True


if __name__ == '__main__':  
    print('usage : python run.py')