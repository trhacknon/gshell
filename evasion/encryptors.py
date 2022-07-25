from itertools import cycle
#from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, DES, DES3, ARC2
from Cryptodome.Random import get_random_bytes
#import chardet

"""
Description: Encrypts and Decrypts shellcode types

Encryption and Decryption requires:
1. Key
2. IV (Initialization Vector)
3. Key Size
4. Block Size
5. Padding
6. Hex Formatting

The method used to define the size is the following:
- get_random_bytes(byte_size_here)

Bytes to bits:
5 Bytes = 40-bit
8 Bytes = 64-bit
16 Bytes = 128-bit 
24 Bytes = 192-bit
32 Bytes = 256-bit
"""

# Problem: The formatting might not be correct in some scenarios

# Formats the bytes array to hex
def hex_format(bytes_obj):
    formatted = ''
    counter = 0
    for byte in bytes_obj:
        counter += 1
        if counter == len(bytes_obj):
            # If this is the last byte don't append a comma
            formatted += '\\x'
            formatted += '%02x' % byte
        else:
            formatted += '\\x'
            formatted += '%02x,' % byte
        # 15 bytes in a row
        if ((counter) % 15 == 0):
            formatted += "\n"
    byte_size = formatted.count("\\x")
    print(f'\n[*] The payload size is: {byte_size}')
    return formatted

# Formats bytes to hex
def byte2hex(bytes_obj):
    hex = '%02x' % int.from_bytes(bytes_obj, byteorder='little')
    return hex

# Pads the shellcode
def pad(shellcode):
    if len(shellcode) % 16 != 0:
        counter = 16 - (len(shellcode) % 16)
        for i in range(counter):
            shellcode += '*'
    return shellcode

# Removes padding from shellcode
def unpad(shellcode):
    shellcode = hex_format(shellcode)
    return shellcode.replace('\\x2a', '')

class xor_encrypt:
    """
    XOR encryption
    """

    def encrypt(shellcode):
        #print(chardet.detect(shellcode.encode()))
        #print(bytes(shellcode, encoding='ascii'))
        print("[*] Raw shellcode:\n{}\n".format(hex_format(bytes(shellcode, encoding='ascii'))))
        session_key = get_random_bytes(1)
        print("[*] Key: {}".format(byte2hex(session_key)))
        enc_shellcode = ''.join(chr(ord(c)^ord(k)) for c,k in zip(shellcode, cycle(str(session_key))))
        print("\n[+] Encrypted shellcode:\n{}".format(hex_format(bytes(enc_shellcode, encoding='ascii'))))
        return enc_shellcode, session_key
    
    def decrypt(enc_shellcode, session_key):
        dec_shellcode = ''.join(chr(ord(c)^ord(k)) for c,k in zip(enc_shellcode, cycle(str(session_key))))
        print("\n[+] Decrypted shellcode:\n{}".format(hex_format(bytes(dec_shellcode, encoding='ascii'))))

class aes_encrypt:
    """
    AES encryption

    EAX mode allows detection of unauthorized modifications.
    - https://pycryptodome.org/en/latest/src/examples.html
    """

    def encrypt(shellcode):
        print("[*] Raw shellcode:\n{}\n".format(hex_format(bytes(shellcode, encoding='ascii'))))
        # 16 Bytes > AES-128 | 24 Bytes > AES-192 | 32 Bytes > AES-256
        session_key = get_random_bytes(32)
        session_iv = get_random_bytes(16)
        print("[*] Key: " + session_key.hex())
        print("[*] IV: " + session_iv.hex())
        cipher = AES.new(session_key, AES.MODE_EAX)
        #nonce = cipher.nonce
        enc_shellcode = session_iv + cipher.encrypt(pad(shellcode).encode("ascii"))
        print("\n[+] Encrypted shellcode:\n{}".format(hex_format(enc_shellcode)))
        return enc_shellcode, session_key, session_iv

    def decrypt(enc_shellcode, session_key, session_iv):
        cipher = AES.new(session_key, AES.MODE_EAX, session_iv)
        dec_shellcode = cipher.decrypt(enc_shellcode)
        #shellcode = unpad(dec_shellcode)
        print("\n[+] Decrypted shellcode:\n{}".format(hex_format(dec_shellcode)))

class des_encrypt:
    """
    DES 64-bit cipher
    """
    def encrypt(shellcode):
        print("[*] Raw shellcode:\n{}\n".format(hex_format(bytes(shellcode, encoding='ascii'))))
        session_key = get_random_bytes(8)
        session_iv = get_random_bytes(8)
        print("[*] Key: " + session_key.hex())
        print("[*] IV: " + session_iv.hex())
        cipher = DES.new(session_key, DES.MODE_OFB)
        enc_shellcode = session_iv + cipher.encrypt(pad(shellcode).encode("ascii"))
        print("\n[+] Encrypted shellcode:\n{}".format(hex_format(enc_shellcode)))
        return enc_shellcode, session_key, session_iv

    def decrypt(enc_shellcode, session_key, session_iv):
        cipher = DES.new(session_key, DES.MODE_OFB, iv=session_iv)
        dec_shellcode = cipher.decrypt(enc_shellcode)
        print("\n[+] Decrypted shellcode:\n{}".format(hex_format(dec_shellcode)))

class tdes_encrypt:
    """
    3DES 128/192-bit cipher
    """
    def encrypt(shellcode):
        print("[*] Raw shellcode:\n{}\n".format(hex_format(bytes(shellcode, encoding='ascii'))))
        session_key = get_random_bytes(24)
        session_iv = get_random_bytes(8)
        print("[*] Key: " + session_key.hex())
        print("[*] IV: " + session_iv.hex())
        cipher = DES3.new(session_key, DES3.MODE_CFB)
        enc_shellcode = session_iv + cipher.encrypt(pad(shellcode).encode("ascii"))
        print("\n[+] Encrypted shellcode:\n{}".format(hex_format(enc_shellcode)))
        return enc_shellcode, session_key, session_iv

    def decrypt(enc_shellcode, session_key, session_iv):
        cipher = DES3.new(session_key, DES3.MODE_OFB, iv=session_iv)
        dec_shellcode = cipher.decrypt(enc_shellcode)
        print("\n[+] Decrypted shellcode:\n{}".format(hex_format(dec_shellcode)))

class rc2_encrypt:
    """
    RC2 40/128-bit cipher
    """
    def encrypt(shellcode):
        print("[*] Raw shellcode:\n{}\n".format(hex_format(bytes(shellcode, encoding='ascii'))))
        session_key = get_random_bytes(16)
        session_iv = get_random_bytes(8)
        print("[*] Key: " + session_key.hex())
        print("[*] IV: " + session_iv.hex())
        cipher = ARC2.new(session_key, ARC2.MODE_CFB)
        enc_shellcode = session_iv + cipher.encrypt(pad(shellcode).encode("ascii"))
        print("\n[+] Encrypted shellcode:\n{}".format(hex_format(enc_shellcode)))
        return enc_shellcode, session_key, session_iv
    
    def decrypt(enc_shellcode, session_key, session_iv):
        cipher = ARC2.new(session_key, ARC2.MODE_OFB, iv=session_iv)
        dec_shellcode = cipher.decrypt(enc_shellcode)
        print("\n[+] Decrypted shellcode:\n{}".format(hex_format(dec_shellcode)))
