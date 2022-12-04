import os

def read(li, *types):
    if os.path.isfile(li):
        data = [ele[:-1].split() for ele in open(li,'r').readlines()]
        if types:
            for i in range(len(data)):
                for j in range(len(types)):
                    data[i][j] = types[j](data[i][j])
        
        return data
    return []