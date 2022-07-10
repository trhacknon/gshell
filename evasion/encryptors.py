from itertools import cycle

def xor_encrypt(data, key):
    """
    XOR encryption
    """

    xored = ''.join(chr(ord(c)^ord(k)) for c,k in zip(data, cycle(key)))
    print(xored)

def aes_encrypt(data, key):
    """
    AES encryption
    """


def caesar_encrypt(data, key):
    """
    Caesar encryption
    """

def des_encrypt(data, key):
    """
    DES encryption
    """

def rc2_encrypt(data, key):
    """
    RC2 encryption
    """
