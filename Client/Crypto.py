

CESAR_SHIFT = 5


class Cesar():

    def __init__(self):
        pass

    @staticmethod
    def encode(input : bytes,shifting : int = CESAR_SHIFT):
        if not input:
            return b''
        
        return bytes((b + shifting) % 256 for b in input)

    @staticmethod
    def decode(input : bytes,shifting : int = CESAR_SHIFT):
        if not input:
            return b''
            
        return bytes((b - shifting) % 256 for b in input)