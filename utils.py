import os

def read(li):
    if os.path.isfile(li):
        return [ele[:-1] for ele in open(li,'r').readlines()]
    return []