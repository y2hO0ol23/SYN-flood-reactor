import logger as lg
import protect.core
import imports

if __name__ == '__main__':  
    loggers = []
    loggers.append(lg.logger(imports.syn_filter, imports.syn, imports.syn_dir))
    for logger in loggers:
        logger.run()

    protect.core.init()
    while True:
        protect.core.start()
    try:
        while True:
            protect.core.start()
    except:
        for logger in loggers:
            logger.stop()