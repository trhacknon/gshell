#!/usr/bin/python3

"""
Author: nozerobit
Twitter: @nozerobit

Description:
GShell is a program to assist penetration testers by generating bind/reverse shells and shellcodes.
"""

from shellcodes import shellcodes
from evasion import encoders, encryptors, obfuscators
#from mdextract import CodeBlock
from mdextract import parse
from argparse import RawTextHelpFormatter
from colorama import Fore, Style, init, AnsiToWin32
#from pprint import pprint
#import os
import sys
import argparse
import ipaddress
import signal
import re


"""
Globals

This variables are used in different functions.

init: Automatically resets the colors (less code)
stream: Windows 32 compatible

colors:
green
yellow
red
blue
cyan
magenta

shells:
bind_shells
reverse_shells
"""

init(autoreset=True)
stream = AnsiToWin32(sys.stderr).stream

green = Style.BRIGHT + Fore.GREEN
yellow = Style.BRIGHT + Fore.YELLOW
red = Style.BRIGHT + Fore.RED
blue = Style.BRIGHT + Fore.BLUE
cyan = Style.BRIGHT + Fore.CYAN
magenta = Style.BRIGHT + Fore.MAGENTA

# For local regex
sbind_shells = open(sys.path[0] + '/shells/' + 'bind_shells.md')
sreverse_shells = open(sys.path[0] + '/shells/' + 'reverse_shells.md')
shollowing_snippets = open(sys.path[0] + '/snippets/' + 'process-hollowing.md')
sinjectors_snippets = open(sys.path[0] + '/snippets/' + 'process-hollowing.md')
# For markdown code extractions
bind_shells = [sys.path[0] + '/shells/' + 'bind_shells.md']
reverse_shells = [sys.path[0] + '/shells/' + 'reverse_shells.md']
hollowing_snippets = [sys.path[0] + '/snippets/' + 'process-hollowing.md']
injectors_snippets = [sys.path[0] + '/snippets/' + 'process-hollowing.md']


def handler(signum, frame):
    """
    Closes the program on Ctrl+C

    This might be used when prompted for questions
    """
    exit(1)

signal.signal(signal.SIGINT, handler)

def verify_ip(ip):
    """
    Verifies that the IP address is valid (IPv4 or IPv6)

    If the IP address is invalid it will exit the process with the return value 1
    """

    try:
        ip = ipaddress.ip_address(ip)
        print(green + '[+] The IPv{1} address: {0} is valid.'.format(ip, ip.version), file=stream)
    except ValueError:
        print(red + '[-] The address/netmask: {0} is invalid.'.format(ip), file=stream)
        exit(1)

def verify_port(port):
    """
    Verifies that the port number is valid

    If the port number is invalid it will exit the process with the return value 1
    """

    try:
        if 1 <= port <= 65535:
            print(green + '[+] The port number: {0} is valid.'.format(port), file=stream)
        else:
            raise ValueError
    except ValueError:
        print(red + '[-] The port number: {0} is invalid.'.format(port), file=stream)
        exit(1)


def list_shells():
    """
    Prints the available shells (names only)

    Detect and filter the names in the markdown code blocks

    Example:
    ```python
    ```
    Filters only 'python'.
    """

    pattern = re.compile(r'^```.*[^\n]')

    try:
        print(green + "[+] These are the available bind shells", file=stream)
        for line in set(sbind_shells):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))
        
        print(green + "[+] These are the available reverse shells", file=stream)
        for line in set(sreverse_shells):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))

        print(green + "[+] These are the available process hollowing code snippets", file=stream)
        for line in set(shollowing_snippets):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))
        
        print(green + "[+] These are the available process injectors code snippets", file=stream)
        for line in set(sinjectors_snippets):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))
    except Exception as e: 
        print(e)
        exit(1)

def find_shell(shell_type, bind, reverse, hollowing, injectors):
    """
    Finds and returns the shell type
    """

    pattern = re.compile(r'^```'+shell_type+r"$")

    if bind is True:
        for line in sbind_shells:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type
    
    if reverse is True:
        for line in sreverse_shells:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type

    if hollowing is True:
        for line in shollowing_snippets:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type

    if injectors is True:       
        for line in sinjectors_snippets:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type

def generate_shells(payload, ip, port, block, language, obfuscate, encoding):
    """
    Generates the shells

    - Filename: bind_shells
    - Filename: reverse_shells

    The placeholder in these files are $ip and $port

    Easy, dynamic, scalable, future-proof, and flexible approach:

    - Detect markdown code blocks and print the code that's inside

    encoding: [url_encoding, 
    base64_encoding,
    base32_encoding,
    base16_encoding]
    """

    if language != "":
        print(green + "[+] Generating "+language+" shells")
    else:
        print(green + "[+] Generating shells")

    #if obfuscate[0] is True:
    if obfuscate is True:
        print(green + "[+] Obfuscating the code", file=stream)
        """
        Obfuscate the IP address
        """
        print(yellow + "[i] Please answer the question below with either: Hex, Octal or None", file=stream)
        answer = input("[!] Which obfuscating method do you want to use for the IP address (Hex/Octal/None)?\n> ")
        if answer.lower() == ("Hex").lower():
            print(blue + "[+] Obfuscating the IP address with hexadecimal values", file=stream)
            ip = obfuscators.ip_obfuscate(ip, answer)
        elif answer.lower() == ("Octal").lower():
            print(blue + "[+] Obfuscating the IP address with octal values", file=stream)
            ip = obfuscators.ip_obfuscate(ip, answer)
        elif answer.lower() == ("None").lower():
            print("[+] Skipping this obfuscation step")
        else:
            print(red + "[-] Error: The answer must be either Hex, Octal or None", file=stream)
            exit(1)
        """
        Obfuscate the port number
        """
        print(yellow + "[i] Please answer the question below with either: Hex, Octal or None", file=stream)
        answer = input("[!] Which obfuscating method do you want to use for the port number (Hex/Octal/None)?\n> ")
        if answer.lower() == ("Hex").lower():
            print(blue + "[+] Obfuscating the port number with hexadecimal values", file=stream)
            port = obfuscators.port_obfuscate(port, answer)
        elif answer.lower() == ("Octal").lower():
            print(blue + "[+] Obfuscating the port number with octal values", file=stream)
            port = obfuscators.port_obfuscate(port, answer)
        elif answer.lower() == ("None").lower():
            print("[+] Skipping this obfuscation step")
        else:
            print(red + "[-] Error: The answer must be either Yes, Octal or None", file=stream)
            exit(1)
        
    for md_filename in payload:
        code_blocks = parse.parse_file(
            md_filename,
            ip = ip,
            port = port,
            parse_blocks = block,
            language = language
        )

        # Print a separator between code blocks
        # Separate each code block with a new line hence ("\n\n")
        cmd = ("\n\n----------------NEXT CODE BLOCK----------------\n\n"
        .join([cb.code for cb in code_blocks]))


        '''
        if obfuscate[1] is True:
            print(blue + "[+] Attempting to obfuscate strings and comments", file=stream)
            new_strings = obfuscators.change_strings(cmd, language)
            no_comments = obfuscators.remove_comments(cmd, language)
            print("\n" + new_strings + no_comments)
        elif encoding[0] is True:
        '''
        if encoding[0] is True:
            print(blue + "[+] Adding URL Encoding\n", file=stream)
            encoders.url_encode(cmd)
        elif encoding[1] is True:
            print(cyan + "[+] Answer with: Windows or Nix", file=stream)
            question = input("[!] Do you want to base64 encode for Windows or Nix?\n> ")
            if question.lower() == ("Windows").lower():
                print(blue + "[+] Adding UTF-16LE base64 Encoding", file=stream)
                print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one by one.\n", file=stream)
                encoders.windows_base64(cmd)
            elif question.lower() == ("Nix").lower():
                print(blue + "[+] Adding ASCII base64 Encoding", file=stream)
                print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one by one.\n", file=stream)
                encoders.base64_encode(cmd)
            else:
                print(red + "[-] Error: The answer must be either Windows or Nix", file=stream)
                exit(0)
        elif encoding[2] is True:
            print(blue + "[+] Adding base32 Encoding", file=stream)
            print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one by one.\n", file=stream)
            encoders.base32_encode(cmd)
        elif encoding[3] is True:
            print(blue + "[+] Adding base16 Encoding", file=stream) 
            print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one by one.\n", file=stream)
            encoders.base16_encode(cmd)
        else:
            print("\n" + cmd)

def print_snippets(snippets, ip, port, block, language):
    """
    Print code snippets

    Replace $ip and $port placeholders
    """

    for md_filename in snippets:
        code_blocks = parse.parse_file(
            md_filename,
            ip = ip,
            port = port,
            parse_blocks = block,
            language = language
        )

        # Separate each code block with a new line hence ("\n\n")
        cmd = ("\n\n----------------NEXT CODE BLOCK----------------\n\n"
        .join([cb.code for cb in code_blocks]))
        print("\n" + cmd)

def generate_shellcode(ip, port, shellcode_os, shellcode_payload):
    """
    Generate the shellcodes
    """

    if shellcode_os[0] is True:
        print(green + "[+] Generating Windows shellcodes", file=stream)
        if shellcode_payload[0] is True:
            return shellcodes.generate_bind_shell.windows_bind_tcp(port)
        if shellcode_payload[1] is True:
            return shellcodes.generate_reverse_shell.windows_reverse_tcp(ip, port)
    if shellcode_os[1] is True:
        print(green + "[+] Generating Linux shellcodes", file=stream)
        if shellcode_payload[0] is True:
            return shellcodes.generate_bind_shell.linux_bind_tcp(port)
        if shellcode_payload[1] is True:
            return shellcodes.generate_reverse_shell.linux_reverse_tcp(ip, port)

def crypter(shellcode, encryptor):
    """
    Encrypt shellcode to bypass SOME AVs 
    """

    if encryptor[0] is True:
        print(green + "[+] Adding XOR encryption\n", file=stream)
        enc_shellcode, session_key = encryptors.xor_encrypt.encrypt(shellcode)
        encryptors.xor_encrypt.decrypt(enc_shellcode, session_key)
    elif encryptor[1] is True:
        print(green + "[+] Adding AES encryption\n", file=stream)
        enc_shellcode, session_key, session_iv = encryptors.aes_encrypt.encrypt(shellcode)
        encryptors.aes_encrypt.decrypt(enc_shellcode, session_key, session_iv)
    elif encryptor[2] is True:
        print(green + "[+] Adding DES encryption\n", file=stream)
        enc_shellcode, session_key, session_iv = encryptors.des_encrypt.encrypt(shellcode)
        encryptors.des_encrypt.decrypt(enc_shellcode, session_key, session_iv)
    elif encryptor[3] is True:
        print(green + "[+] Adding 3DES encryption\n", file=stream)
        enc_shellcode, session_key, session_iv = encryptors.tdes_encrypt.encrypt(shellcode)
        encryptors.tdes_encrypt.decrypt(enc_shellcode, session_key, session_iv)
    elif encryptor[4] is True:
        print(green + "[+] Adding RC2 encryption\n", file=stream)
        enc_shellcode, session_key, session_iv = encryptors.rc2_encrypt.encrypt(shellcode)
        encryptors.rc2_encrypt.decrypt(enc_shellcode, session_key, session_iv)
    else:
        print(red + "[-] Missing an encryptor", file=stream)

def main():
    """
    Parse the arguments and decides the program flow

    This is also the help menu

    allow_abbrev=False; Disables abbreviations
    """

    parser = argparse.ArgumentParser(description=f"""

 ██████  ███████ ██   ██ ███████ ██      ██      
██       ██      ██   ██ ██      ██      ██      
██   ███ ███████ ███████ █████   ██      ██      
██    ██      ██ ██   ██ ██      ██      ██      
 ██████  ███████ ██   ██ ███████ ███████ ███████ 


Generate shellcodes, bind shells and/or reverse shells with style

            Version: 1.3.1 dev
            Author: nozerobit
            Twitter: @nozerobit
""", 
    formatter_class=RawTextHelpFormatter, add_help=False, allow_abbrev=False)
    parser._optionals.title = "Options"
    parser.add_argument('-i', '--ip', metavar="<IP ADDRESS>", action='store', dest='ip', type=str, help='Specify the IP address')
    parser.add_argument('-p', '--port', metavar="<PORT NUMBER>", action='store', dest='port', type=int, help='Specify the port number')
    parser.add_argument('-s', '--shell',  metavar="<SHELL TYPE>", action='store', default='', dest='shell', type=str, help='Specify a shell type (python, nc, bash, etc)')

    # Payload Type
    payload_arg = parser.add_argument_group('Payload Types')
    payload_arg.add_argument("-r", "--reverse", action="store_true", dest='reverse', help="Victim communicates back to the attacking machine")
    payload_arg.add_argument("-b", "--bind", action="store_true", dest='bind', help="Open up a listener on the victim machine")

    # Snippets Type
    snippets_arg = parser.add_argument_group('Snippets Types')
    snippets_arg.add_argument("--hollowing", action="store_true", dest='hollowing', help="Print process hollowing code snippets")
    snippets_arg.add_argument("--injector", action="store_true", dest='injector', help="Print process injector code snippets")

    # Shellcodes
    shellcode_arg = parser.add_argument_group('Shellcode Types')
    shellcode_arg.add_argument("--shellcode", action="store_true", required=False, help="Generate shellcodes, requires --srev or --sbind and --windows or --linux")
    shellcode_arg.add_argument("--srev", action="store_true", dest='srev', help="Reverse shell shellcode")
    shellcode_arg.add_argument("--sbind", action="store_true", dest='sbind', help="Bind shell shellcode")
    shellcode_arg.add_argument("--windows", action='store_true', dest='windows', help="Windows shellcode")
    shellcode_arg.add_argument("--linux", action='store_true', dest='linux', help="Linux shellcode")
    
    # Encodings Options
    encodings = parser.add_argument_group('Encoding Options')
    encodings.add_argument("--base64", action="store_true", required=False, help="Add base64 encoding to payload types")
    encodings.add_argument("--base32", action="store_true", required=False, help="Add base32 encoding to payload types")
    encodings.add_argument("--base16", action="store_true", required=False, help="Add base16 encoding to payload types")
    encodings.add_argument("--url", action="store_true", required=False, help="Add URL encoding to payload types")

    # Obfuscation Options
    obfuscation = parser.add_argument_group("Obfuscation Options")
    obfuscation.add_argument("--obfuscate", action="store_true", required=False, help="Obfuscates the IP address and port number for payload types")
    #obfuscation.add_argument("--obfuscate-strings", action="store_true", required=False, help="Obfuscates the strings and removes comments for payload types" )

    # Encryptors Options
    encriptadores = parser.add_argument_group("Encryptor Options")
    encriptadores.add_argument("--xor", action="store_true", required=False, help="XOR encrypt shellcode types")
    encriptadores.add_argument("--aes", action="store_true", required=False, help="AES encrypt shellcode types")
    encriptadores.add_argument("--des", action="store_true", required=False, help="DES encrypt shellcode types")
    encriptadores.add_argument("--tdes", action="store_true", required=False, help="3DES encrypt shellcode types")
    encriptadores.add_argument("--rc2", action="store_true", required=False, help="RC2 encrypt shellcode types")

    # AMSI Options
    #amsi = parser.add_argument_group("AMSI Options")
    #amsi.add_argument("--opcodes", action="store_true", required=False, help="Convert payload types code to opcodes")
    #amsi.add_argument("--reflection", action="store_true", required=False, help="Convert payload types code to reflection")

    # Markdown Options
    markdown = parser.add_argument_group("Markdown Options")
    markdown.add_argument("--no-block", action="store_true", default = False, help="Skip ```\ncode\nblocks\n``` while parsing")
    #markdown.add_argument("--language", "-l", default="", help="Filter the blocks by ```language\ncode\ncode\n```")
    #markdown.add_argument("--debug", default=False, action="store_true", help="Show debug output")

    # Assistance / Help
    help_arg = parser.add_argument_group('Help Options')
    help_arg.add_argument('--list', action='store_true', help='List the available shell types')
    help_arg.add_argument('--advice', action='store_true', dest='advice', help='Print advice and tips to get connections')
    help_arg.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit') 

    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    args = parser.parse_args()

    # Options
    ip = args.ip
    port = args.port
    shell = args.shell
    # Payloads
    reverse = args.reverse
    bind = args.bind
    # Code Snippets
    hollowing = args.hollowing
    injectors = args.injector
    # Shellcodes
    shellcode = args.shellcode
    shellcode_windows = args.windows
    shellcode_linux = args.linux
    shellcode_reverse = args.srev
    shellcode_bind = args.sbind
    # Encodings
    base64_encoding = args.base64
    base32_encoding = args.base32
    base16_encoding = args.base16
    url_encoding = args.url
    # Obfuscation
    ob = args.obfuscate
    #ob2 = args.obfuscate_strings
    # Encryptors
    xor_encrypt = args.xor
    aes_encrypt = args.aes
    des_encrypt = args.des
    tdes_encrypt = args.tdes
    rc2_encrypt = args.rc2
    # Markdown
    block = not args.no_block
    #language = args.language
    #debug = args.debug
    # Help
    advice = args.advice
    shell_list = args.list

    all_main = [ip, port, shell]
    all_payloads = [reverse, bind]
    all_snippets = [hollowing, injectors]
    all_encodings = [url_encoding, 
    base64_encoding,
    base32_encoding,
    base16_encoding]
    #all_obfuscation = [ob, ob2]
    shellcode_os = [shellcode_windows, shellcode_linux]
    shellcode_payload = [shellcode_bind, shellcode_reverse]
    all_encryptors = [xor_encrypt,
    aes_encrypt,
    des_encrypt,
    tdes_encrypt,
    rc2_encrypt]
    #other_options = [ob, ob2, shellcode]
    other_options = [ob, shellcode]
    help_options = [advice, shell_list]

    def verify_ip_and_port(ip, port):
        if ip is not None and port is not None:
            verify_ip(ip)
            verify_port(port)
        else:
            print(yellow + "[!] Please specify an IP address and a port number, use the option -h, --help", file=stream)
            exit(1)

    def verify_port_only(port):
        if port is not None:
            verify_port(port)
        else:
            print(yellow + "[!] Please specify a port number, use the option -h, --help", file=stream)
            exit(1)

    if advice is True and shell_list is True:
        print(red + "[-] Can't use both --advice and --list options at the same time", file=stream)
        exit(1)

    if any(help_options) == True and any(other_options) == True:
        print(red + "[-] Can't use both help options and other options at the same time", file=stream)
        exit(1)

    if any(help_options) == True and any(all_main) == True:
        print(red + "[-] Can't use both help options and main options at the same time", file=stream)
        exit(1)

    if ((any(help_options) == True and any(all_payloads) == True) or (any(help_options) == True and any(all_snippets) == True)):
        print(red + "[-] Can't use a help option and other options at the same time", file=stream)
        exit(1)

    if ((any(help_options) == True and any(all_encodings) == True) or (any(help_options) == True and any(all_encryptors) == True)):
        print(red + "[-] Can't use a help option and other options at the same time", file=stream)
        exit(1)

    if ((any(help_options) == True and any(shellcode_os) == True) or (any(help_options) == True and any(shellcode_payload) == True)):
        print(red + "[-] Can't use a help option and other options at the same time", file=stream)
        exit(1)

    if advice is True:
        print("""
Advice: The obvious things
Tips: The not so obvious things

Before: Verify for defensive mechanism and devices such as:
    - Firewalls (Software & Hardware)
    - IDS/IPS (Software & Hardware)
    - System Rules
    - AVs/EDRs

1. Advice: Make sure that the port is not blocked
2. Advice: Make sure that you're using the correct IP address and that's active/up.
3. Advice: Make sure that you're using the correct port and that's active/listening for connections.
4. Advice: Make sure that the language or tool is installed in the target system.
5. Advice: Make sure that there's an existing shell (bash, sh, zsh, fish, rbash, etc).
6. Tip: When using a reverse shell try to specify a listening port that's open externally
    - For example, if you find that port 443 is open but you try to establish a connection on port 9993 and you don't get a connection back,
        then most likely a software/host firewall is blocking it. Therefore, always try ports that are externally open first.
7. Tip: When a reverse shell fails try to encode it to bypass potential filters.
8. Tip: When a bind shell fails, verify that there are no middle devices such as IDS/IPS, hardware/software firewall, or system rules that avoid ports from being in the listening state.
9. Tip: When there's a black list and a white list. Enumerate the black list first and then the white list.
    - After taking notes of the allowed words or characters (white list), try to manually build a command or code. 
10. Tip: If there's an AV/EDR then we should encode, encrypt, and overall try to obfuscate the command/code so that's not detected.
            """)
        exit(0)

    if shell_list is True:
        list_shells()
        exit(0)

    if bind is True and reverse is True:
        print(red + "[-] Can't use both --bind and --reverse options at the same time", file=stream)
        exit(1)

    if ((url_encoding==True and base64_encoding==True) or (url_encoding==True and base32_encoding==True)):
        print(red + "[-] Can't use multiple encodings at the same time", file=stream)
        exit(1)
        
    if ((url_encoding==True and base16_encoding==True) or (base32_encoding==True and base16_encoding==True)):
        print(red + "[-] Can't use multiple encodings at the same time", file=stream)
        exit(1)

    if ((base64_encoding==True and base32_encoding==True) or (base64_encoding==True and base16_encoding==True)):
        print(red + "[-] Can't use multiple encodings at the same time", file=stream)
        exit(1)

    if any(all_payloads) == True and any(all_snippets) == True:
        print(red + "[-] Can't use a payload type and a code snippet type at the same time", file=stream)
        exit(1)
    
    if any(all_payloads) == True and shellcode is True:
        print(red + "[-] Can't use a payload type and a shellcode type at the same time", file=stream)
        exit(1)

    if any(all_payloads) == True and any(shellcode_os) == True:
        print(red + "[-] Can't use payload options and shellcode types at the same time", file=stream)
        exit(1)

    if any(all_payloads) == True and any(shellcode_payload) == True:
        print(red + "[-] Can't use payload options and shellcode types at the same time", file=stream)
        exit(1)

    if any(all_payloads) == True and any(all_encryptors) == True:
        print(red + "[-] Can't use encryption options and payload types at the same time", file=stream)
        exit(1)

    if hollowing==True and injectors==True:
        print(red + "[-] Can't use process hollowing and process injectors code snippets at the same time", file=stream)
        exit(1)

    if any(all_snippets) == True and any(shellcode_os) == True:
        print(red + "[-] Can't use shellcode and code snippets at the same time", file=stream)
        exit(1)

    if any(all_snippets) == True and any(shellcode_payload) == True:
        print(red + "[-] Can't use shellcode and code snippets at the same time", file=stream)
        exit(1)
    
    if any(all_snippets) == True and any(all_encryptors) == True:
        print(red + "[-] Can't use encryptors and code snippets at the same time", file=stream)
        exit(1)

    '''
    if any(all_obfuscation) == True and any(all_snippets) == True:
        print(red + "[-] Can't use code snippets and obfuscation options at the same time", file=stream)
        exit(1)

    if any(all_obfuscation) == True and any(all_encryptors) ==True:
        print(red + "[-] Can't use encryption options and obfuscation at the same time", file=stream)
        exit(1)
    '''

    if ob is True and any(all_snippets) == True:
        print(red + "[-] Can't use code snippets and obfuscation options at the same time", file=stream)
        exit(1)

    if ob is True and any(all_encryptors) == True:
        print(red + "[-] Can't use encryption options and obfuscation at the same time", file=stream)
        exit(1)

    if ob is True and shellcode == True:
        print(red + "[-] Can't use obfuscation options and shellcode at the same time", file=stream)
        exit(1)

    if shellcode == True and any(all_snippets) == True:
        print(red + "[-] Can't use code snippets and shellcode options at the same time", file=stream)
        exit(1)

    if shellcode == True and any(all_encodings) == True:
        print(red + "[-] Can't use enconding options and shellcode at the same time", file=stream)
        exit(1)

    if shell is not None and shell != "":
        shell_type = find_shell(shell, bind, reverse, hollowing, injectors)
        #print(f'{shell_type}')
        if shell_type is not None and shell_type != "":
            print(green + "[+] Shell type is valid", file=stream)
        else:
            print(red + "[-] Shell type doesn't exists", file=stream)
            exit(1)

    if bind is True:
        verify_port_only(port)
        print(green + "[+] Preparing bind shells", file=stream)
        generate_shells(bind_shells, ip, port, block, shell, ob, all_encodings)
        exit(0)

    if reverse is True:
        verify_ip_and_port(ip, port)
        print(green + "[+] Preparing reverse shells", file=stream)
        generate_shells(reverse_shells, ip, port, block, shell, ob, all_encodings)
        exit(0)

    if hollowing is True:
        verify_ip_and_port(ip, port)
        print(green + "[+] Preparing process hollowing code snippets", file=stream)
        print_snippets(hollowing_snippets, ip, port, block, shell)
        exit(0)
    
    if injectors is True:
        verify_ip_and_port(ip, port)
        print(green + "[+] Preparing process injectors code snippets", file=stream)
        print_snippets(injectors_snippets, ip, port, block, shell)
        exit(0)

    if shellcode is True and shellcode_bind is False and shellcode_reverse is False:
        print(yellow + "[-] Please specify a shellcode payload, use --sbind or --srev")
        exit(1)

    if shellcode is True:
        if shellcode_bind is True and shellcode_reverse is True:
            print(red + "[-] Can't use both shellcode types at the same time", file=stream)
            exit(1)

        if shellcode_linux is True and shellcode_windows is True:
            print(red + "[-] Can't use both windows shellcodes and linux shellcodes at the same time", file=stream)
            exit(1)

        if shellcode_linux is False and shellcode_windows is False:
            print(yellow + "[-] Please specify an operating system with --linux or --windows", file=stream)
            exit(1)
                
        if shellcode_bind is True:
            verify_port_only(port)
            print(green + "[+] Generating bind shell shellcodes", file=stream)
            shellcode_data = generate_shellcode(ip, port, shellcode_os, shellcode_payload)
            #exit(0)

        if shellcode_reverse is True:
            verify_ip_and_port(ip, port)
            address = ipaddress.ip_address(ip)
            if isinstance(address, ipaddress.IPv4Address):
                print(blue + "[+] IPv4 address detected".format(address), file=stream)
            elif isinstance(address, ipaddress.IPv6Address):
                print(blue + "[+] IPv6 address detected".format(address), file=stream)
                print(red + "[-] IPv6 is not supported for reverse shell shellcodes yet, feel free to contribute or make a pull requests.", file=stream)
                exit(1)
            print(green + "[+] Generating reverse shell shellcodes", file=stream)
            shellcode_data = generate_shellcode(ip, port, shellcode_os, shellcode_payload)
            #exit(0)

        if any(all_encryptors) == True:
            crypter(shellcode_data, all_encryptors)
            exit(0)
        else:
            print(cyan + "[+] Answer with: Yes or No", file=stream)
            question = input("[!] Do you want to print using the multi-liner format (Yes/No)?\n> ")
            if question.lower() == ("Yes").lower():
                print(blue + "[+] Using multi-line format", file=stream)
                print("\n" + re.sub("(.{56})", "\\1\n", shellcode_data, 0, re.DOTALL))
            elif question.lower() == ("No").lower():
                print(blue + "[+] Using one-liner format", file=stream)
                print("\n" + shellcode_data)
                exit(0)
            else:
                print(red + "[-] Error: The answer must be either Yes or No", file=stream)
                exit(1)
            
if __name__ == "__main__":
    main()