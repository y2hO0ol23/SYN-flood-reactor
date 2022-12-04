import logger as lg
import protect.core
import imports
import os

drop_all_syn = '-d %d --protocol tcp --tcp-flags SYN,RST,ACK,FIN SYN -j DROP'%imports.ip
print(drop_all_syn)

if __name__ == '__main__':  
    os.system('iptables -I INPUT 1 %s'%drop_all_syn)

    loggers = []
    loggers.append(lg.logger(imports.syn_filter, imports.syn, imports.syn_dir))
    for logger in loggers:
        logger.run()

    protect.core.init()

    try:
        while True:
            protect.core.start()
    except Exception as e:
        for logger in loggers:
            logger.stop()
        
        protect.core.stop()
        os.system('iptables -D INPUT %s'%drop_all_syn)
