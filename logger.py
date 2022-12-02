from scapy.all import *
import threading
import os
import time as tm

def try_mkdir(path):
    try:
        os.mkdir(path)
    except:
        pass

class logger():
    def __init__(self, filter: str, func, directory:str) -> None:
        self.end = True
        self.filter = filter
        self.log_path = './log/'
        self.log = func
        try_mkdir('./log')
        if filter != "":
            try_mkdir('./log/' + directory)
            self.log_path += directory + '/'


    def manage(self, packet:Packet)->None:
        filename = self.log_path + tm.strftime('%Y-%m-%d_%I.%M.%S_%p.log', tm.localtime(tm.time()))
        thread = threading.Thread(target = self.log, args=(filename, packet))
        thread.start()
        

    def master(self)->None:
        slave = threading.Thread(target = sniff, kwargs={"prn" : self.manage, "count" : 0, "filter" : self.filter}, daemon=True)

        slave.start()
        while not self.end: pass

            
    def run(self)->None:
        self.end = False

        logger = threading.Thread(target = self.master)
        logger.start()


    def stop(self)->None:
        self.end = True


if __name__ == '__main__':  
    print('usage : python run.py')