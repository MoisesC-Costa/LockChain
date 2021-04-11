from typing import Union
from rsa import newkeys, PublicKey, PrivateKey
from os import PathLike
from hashlib import sha256
import secrets

class CryptMessage:
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
            lenght_segment = lenght_key - 72
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
                    if (leng := lenght_int(rand_num)) != 32:
                        continue

                    prefix = int.to_bytes(rand_num, leng, 'big')
                    break

                verificador = sha256(prefix + frame).digest()
                packet = verificador + prefix + frame
                packet = int.from_bytes(packet, 'big')                
                calc = pow(packet, self.key.e, self.key.n)
                message += int.to_bytes(calc, lenght_key, 'big')

            self.data = message
                
            return True

    def decrypt(self) -> bool:
        if type(self.key) != PrivateKey:
            return False
        
        else:
            data_segments = []
            lenght_key = lenght_int(self.key.n)
            message = b""
            
            frame = b""
            for byte in self.data:
                frame += int.to_bytes(byte, 1, 'big')
                
                if len(frame) == lenght_key:
                    data_segments.append(frame)
                    frame = b""
                    
            if frame != b"":
                data_segments.append(frame)
            
            for packet in data_segments:
                pct_value = int.from_bytes(packet, 'big')
                calc = pow(pct_value, self.key.d, self.key.n)
                data = int.to_bytes(calc, lenght_int(calc), 'big')
                verificador = data[:32]
                
                if sha256(frame:= data[32:]).digest() == verificador:
                    message += frame[32:]

                else:
                    print(data)
                    return False
        
        self.data = message
        return True
  

class CryptFile(CryptMessage):
    def __init__(self, file: PathLike = "", key: Union[PrivateKey, PublicKey] = None) -> None:        
        try:
            with open(file, 'rb') as by_file:
                data = by_file.read()
            
        except:
            data = b""
                
        super().__init__(data, key)

        self.file = file

    def set_file(self, file: PathLike) -> bool:
        try:
            with open(file, 'rb') as by_file:
                data = by_file.read()
            
        except FileNotFoundError:
            return False
        
        self.data = data
        return True

    def encrypt(self) -> bool:
        try:
            if super().encrypt():
                with open(self.file, "wb") as by_file:
                    by_file.write(self.data)

                return True
            
            else:
                return False
            
        except:
            return False

    def decrypt(self) -> bool:
        try:
            if super().decrypt():
                with open(self.file, "wb") as by_file:
                    by_file.write(self.data)
                    
                    return True
            
            else:
                return False
        
        except:
            return False


def lenght_int(num : int = 0) -> int:
    bits = int.bit_length(num)
    
    if not bits % 8:
        return bits // 8
    
    else:
        return (bits // 8) + 1
