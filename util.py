def b2s(b):
    if type(b) is not str:
        return b.decode('utf-8')
    return b

def s2b(s):
    if type(s) is str:
        return s.encode('utf-8')
    return s
