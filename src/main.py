from lockchain import *
PATH = "diversos\\test.png"
PATH_FILE = "diversos\\image (1).png"

if __name__ == "__main__":
    with open(PATH_FILE, 'rb') as file:
        data = file.read()
        
    with open(PATH, 'wb') as file:
        file.write(data)
    
    
    pv = newkeys(1024)[1]
    file = CryptFile(PATH, pv)
    file.encrypt()
    file.decrypt()