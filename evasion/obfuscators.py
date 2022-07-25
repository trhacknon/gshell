#import re
#import random
#import string
import ipaddress
#import itertools
#import io

"""
Description: Contains obfuscators for payload types.

sec: Is used to find the separator
sep: Is used to print the separator
"""

sep = "\n----------------NEXT CODE BLOCK----------------\n"
sec = "----------------NEXT CODE BLOCK----------------\n"

def change_strings(data, language):
    """
    Change strings into random characters
    """

    '''
    print("[+] Attempting to obfuscate strings")
    for line in io.StringIO(data):
        if line == sec:
            print(sep.strip("\n"))
        elif sec != line:
            if language == "bash":
                # Filter what's inside the strings
                print("[+] Found a string")
                # obfuscated_strings = randomize the characters
    else:
        print("[-] Didn't obfuscated the strings")
    '''
    
    #return obfuscated_strings

def remove_comments(data, language):
    """
    Remove comments in any language
    """

    '''
    print("[+] Attempting to remove comments")
    for line in io.StringIO(data):
        if line == sec:
            print(sep.strip("\n"))
        elif sec != line:
            if language == "bash":
                # Search for comments using the correct syntax
                print("[+] Found a comment")
                # removed_comments = code to remove comments   
        else:
            print("[-] Didn't found any comments")
    '''

    # return removed_comments

def ip_obfuscate(ip, answer):
    """
    Obfuscate an IPv4 and IPv6 address by converting it to decimal, hex, 
    octal, or a combination of the three.

    IPv4:
    - 16,777,216
    - 65,536
    - 256
    """

    address = ipaddress.ip_address(ip)

    try:
        if isinstance(address, ipaddress.IPv4Address):
            print("[+] IPv4 address detected".format(address))
            print("[+] Attempting to obfuscate an IPv4 address")
            octects = ip.split('.')
            decimal = int(octects[0]) * 16777216 + int(octects[1]) * 65536 + int(octects[2]) * 256 + int(octects[3])
            if answer.lower() == 'hex':
                ip = hex(decimal)
            elif answer.lower() == 'octal':
                ip = oct(decimal)
            else:
                print("[-] Didn't obfuscated the IPv4 address")
        elif isinstance(address, ipaddress.IPv6Address):
            print("[+] IPv6 address detected".format(address))
            print("[-] IPv6 is still not supported for obfuscation, feel free to contribute or make a pull requests.")
            exit(1)
    except ValueError:
        print("[-] The address {} is an invalid IP address".format(address))
        
    return str(ip)


def port_obfuscate(port, answer):
    """
    Obfuscates the port number by converting integers with hexadecimal or octal values.
    """

    if answer.lower() == 'hex':
        port = hex(port)
    elif answer.lower() == 'octal':
        port = oct(port)
    else:
        print("[-] Didn't obfuscated the IPv4 address")

    return port