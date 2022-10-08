
"""
Simple Webserver that can send and recieve HTTP packets.
This server will be able to handle one HTTP GET request at a time
using persistent HTTP connections (HTTP 1.1)

This server will be able to serve GET requests for html and png
files located in the same directory as this server.

Written by Eric Lin eric.lin6.2020@gmail.com 7/10/2022
"""

import sys
import re
from socket import *
import os.path


if __name__ == "__main__":
    try:
        server_port = int(sys.argv[1])
    except:
        print(f"Usage: {sys.argv[0]} <server-port>")

   # create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    
    # bind socket to port number
    serverSocket.bind(('localhost', server_port))

    
    # begin listening
    serverSocket.listen(1) 
    
    print(f"[LISTENING] Server port: {server_port}")
    
    while 1:
        connectionSocket, addr = serverSocket.accept()

        print(f"[NEW CONNECTION] {addr} connection established")
        # When a client knocks on this door, the program invokes the accept( ) method for serverSocket, which creates a new socket in the server, 
        # called connectionSocket, dedicated to this particular client. The client and server then complete the handshaking, creating a TCP connection 
        # between the client’s clientSocket and the server’s connectionSocket. With the TCP connection established, the client and server can now 
        # send bytes to each other over the connection. With TCP, all bytes sent from one side not are not only guaranteed to arrive at the other 
        # side but also guaranteed to arrive in order

        msg = connectionSocket.recv(1024)
        #wait for data to arrive from the client
        
        request = re.match("^GET /(.*?) HTTP/1.1\r\n", msg.decode())
        
        # only servers get requests
        if not request:
            continue
        
        """ 
        print(request.group(1))
        print(f"File exists: {os.path.isfile(request.group(1))}")
        print(f"Is HTML: {request.group(1).endswith('.html')}")
        print(f"Is PNG: {request.group(1).endswith('.png')}")
        print(msg.decode())
        """
        # send basic index.html
        if os.path.isfile(request.group(1)) and request.group(1).endswith(".html"):

            
            # http response basic header
            connectionSocket.send(b'HTTP/1.1 200 OK\n')
            connectionSocket.send(b'Content-Type: text/html\n')
            connectionSocket.send(b'\n')
            
            with open(request.group(1), "rb") as index:
                connectionSocket.send(b"".join(index.readlines()))


        # send png image files
        elif os.path.isfile(request.group(1)) and request.group(1).endswith(".png"):

            # http response basic header
            connectionSocket.send(b'HTTP/1.1 200 OK\n')
            connectionSocket.send(b'Content-Type: image/png\n')
            connectionSocket.send(b'\n')
            
            with open(request.group(1), "rb") as index:
                connectionSocket.send(b"".join(index.readlines()))

        # file does not exist
        else:

            # error code
            connectionSocket.send(b'HTTP/1.1 404 Not Found\n')
            
        connectionSocket.close()

    
    serverSocket.close()