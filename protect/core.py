import time as tm
import imports
from scapy.all import *

import protect.syn

global next_time

def init()->None:
    global next_time
    next_time = int(tm.time()) + 2

def start()->None:
    global next_time
    time = tm.time()
    if next_time == int(time) - imports.delay:
        next_time += 1
        protect.syn.run(time)

        while len(imports.queue) > 0:
            ip, cmd, rmtime = imports.queue[0]
            if rmtime <= time:
                os.system('echo "%s" | at now +30 minutes'%cmd)
                print(ip,'=> drop')
                imports.queue = imports.queue[1:]
            else:
                break
    
    
def stop()->None:
    protect.syn.stop()