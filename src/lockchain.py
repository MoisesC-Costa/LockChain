from typing import Union
from rsa import key, newkeys, PublicKey, PrivateKey
import secrets

class CryptMensage:
    def __init__(self, data : bytes = b"", key : Union[PrivateKey, PublicKey] = None) -> None:
        self.data = data
        self.key = key
    
    def set_data(self, data : bytes = b"") -> bool:
        if type(data) != bytes:
            return False
        
        else:
            self.data = data
            return True

    def set_key(self, key : Union[PrivateKey, PublicKey]) -> bool:
        if type(key) == PrivateKey:
            self.key = key
        
            return True
            
        elif type(key) == PublicKey:
            self.key = key
        
            return True
            
        else:
            
            return False
        
    def get(self) -> bytes:
        return self.data

    def encrypt(self) -> bool:
        if type(self.key) != PrivateKey and type(self.key) != PublicKey:
            return False
        
        else:
            lenght_key = lenght_int(self.key.n)
            lenght_segment = lenght_key - 33
            data_segments = []
            message = b""
            
            frame = b""
            for byte in self.data:
                frame += int.to_bytes(byte, 1, 'big')
                
                if len(frame) == lenght_segment:
                    data_segments.append(frame)
                    frame = b""
            data_segments.append(frame)
        
            for frame in data_segments:
                while True:
                    rand_num = secrets.randbits(32 * 8)
                    prefix = int.to_bytes(rand_num, lenght_int(rand_num), 'big')
                    
                    packet = prefix + frame
                    packet = int.from_bytes(packet, 'big')
                    
                    if packet < self.key.n:
                        break
                
                calc = pow(packet, self.key.e, self.key.n)
                message += int.to_bytes(calc, lenght_key, 'big')

            self.data = message
                
            return True

    def decrypt(self) -> bool:
        if type(self.key) != PrivateKey:
            return False
        
        else:
            data_segments = []
            key_lenght = lenght_int(self.key.n)
            message = b""
            
            frame = b""
            for byte in self.data:
                frame += int.to_bytes(byte, 1, 'big')
                
                if len(frame) == key_lenght:
                    data_segments.append(frame)
                    frame = b""
            data_segments.append(frame)
        
            for packet in data_segments:
                pct_value = int.from_bytes(packet, 'big')
                calc = pow(pct_value, self.key.d, self.key.n)
                message += int.to_bytes(calc, lenght_int(calc), 'big')[32:]
        
        self.data = message
        return True
        
def lenght_int(num : int = 0) -> int:
    bits = int.bit_length(num)
    
    if not bits % 8:
        return bits // 8
    
    else:
        return (bits // 8) + 1
