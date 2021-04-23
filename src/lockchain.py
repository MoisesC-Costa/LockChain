from typing import Union
from rsa import newkeys, key, PublicKey, PrivateKey
from os import PathLike
from hashlib import sha256
import secrets

class CryptMessage:
    def __rand_prefix() -> bytes:
        while True:
            value_prefix = secrets.randbits(32 * 8)
            
            if len(data := int_bytes(value_prefix)) == 32:
                return data

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
        if (type(self.key) != PrivateKey) and (type(self.key) != PublicKey):
            return False
        
        lenght_key = length_int(self.key.n)
        lenght_seg = lenght_key - 72
        data = b""
        
        for sep in range(0, lenght_data := len(self.data), lenght_seg):
            if (sep + lenght_seg) < lenght_data:
                segment = self.data[sep: sep + lenght_seg]
                
            else:
                segment = self.data[sep:]

            frame = segment
            verificador = sha256(frame).digest()
            packet_prefix = CryptMessage.__rand_prefix()
            packet = packet_prefix + verificador + frame

            value_packet = int.from_bytes(packet, 'big')
            calc = pow(value_packet, self.key.e, self.key.n)
            data += int.to_bytes(calc, lenght_key, 'big')
            
        self.data = data
        return True
            
    def decrypt(self) -> bool:
        if type(self.key) != PrivateKey:
            return False
        
        lenght_key = length_int(self.key.n)
        lenght_sep = lenght_key - 72
        data = b''
        
        for sep in range(0, lenght_data := len(self.data), lenght_key):
            if (sep + lenght_key) < lenght_data:
                segment = self.data[sep: sep + lenght_key]
                
            else:
                segment = self.data[sep:]

            value_segment = int.from_bytes(segment, 'big')
            calc = pow(value_segment, self.key.d, self.key.n)
            packet = int.to_bytes(calc, length_int(calc), 'big')
            
            checksum = packet[32:64]
            message = packet[64:]
            
            if checksum != sha256(message).digest():
                print("Falhou o check sum")
            
            data += message

            
        self.data = data
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


def length_int(num : int = 0) -> int:
    bits = int.bit_length(num)
    
    if bits % 8 == 0:
        return bits // 8
    
    else:
        return ((bits // 8) + 1)

int_bytes = lambda x : int.to_bytes(x, length_int(x), 'big')
bytes_int = lambda x: int.from_bytes(x, 'big')