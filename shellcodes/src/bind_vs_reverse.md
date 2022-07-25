# Algorithm steps

## Server | Bind Shell

1. Initialize Winsock.
2. Create a socket.
3. Bind the socket.
4. Listen on the socket for a client.
5. Accept a connection from a client.
6. Receive and send data. (Shell Process)
7. Disconnect.


## Client | Reverse Shell

1. Initialize Winsock.
2. Create a socket.
3. Connect to the server.
4. Send and receive data. (Shell Process)
5. Disconnect.