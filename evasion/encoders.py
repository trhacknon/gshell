from urllib.parse import quote_plus
import base64
import io

"""
Description: Contains encodings for payload types and others for shellcode types.

sec: Is used to find the separator
sep: Is used to print the separator
"""

sep = "\n----------------NEXT CODE BLOCK----------------\n"
sec = "----------------NEXT CODE BLOCK----------------\n"

def url_encode(data):
    """
    URL-encode a byte stream and a few other characters
    """
    for line in io.StringIO(data):
        if line == sec:
            print(sep.strip("\n"))
        elif sec != line:
            url_encoded = quote_plus(line.strip("\n"))
            print(url_encoded)

def base64_encode(data):
    """
    base64 encode a byte stream
    """
    for line in io.StringIO(data):
        if line == sec:
            print(sep.strip("\n"))
        elif sec != line:
            base64_encode = line.strip("\n")
            encoding_bytes = base64_encode.encode('ascii')
            base64_bytes = base64.b64encode(encoding_bytes)
            print(base64_bytes.decode())

def base32_encode(data):
    """
    base32 encode a byte stream

    Some systems don't have base64 installed
    but do have base32 installed
    """
    for line in io.StringIO(data):
        if line == sec:
            print(sep.strip("\n"))
        elif sec != line:
            base32_encode = line.strip("\n")
            encoding_bytes = base32_encode.encode('ascii')
            base32_bytes = base64.b32encode(encoding_bytes)
            print(base32_bytes.decode())

def base16_encode(data):
    """
    base16 encode a byte stream

    Usually used to encode small bytes
    """
    for line in io.StringIO(data):
        if line == sec:
            print(sep.strip("\n"))
        elif sec != line:
            base16_encode = line.strip("\n")
            encoding_bytes = base16_encode.encode('ascii')
            base16_bytes = base64.b16encode(encoding_bytes)
            print(base16_bytes.decode())

def windows_base64(data):
    """
    Windows uses UTF16-LE Unicode strings to byte sequences
    """
    for line in io.StringIO(data):
        if line == sec:
            print(sep.strip("\n"))
        elif sec != line:
            base64_encode = line.strip("\n")
            encoding_bytes = base64_encode.encode('utf-16-le')
            base64_bytes = base64.b64encode(encoding_bytes)
            print(base64_bytes.decode())