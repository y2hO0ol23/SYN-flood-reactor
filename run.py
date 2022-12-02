import logger as lg

if __name__ == '__main__':  
    logger = lg.logger('ip')
    logger.run()
    try:
        while True: pass
    except KeyboardInterrupt:
        logger.stop()