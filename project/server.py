#! /usr/bin/env python3 


from socket import *
import pickle
import platform
import threading
import sys

MAX_SIZE = 4096

#READ FROM CREDENTIALS.TXT FOR ACCOUNTS



def authenticate(connection_socket, addr, msg_obj):
    print(f"[AUTHENTICATION REQUEST] {addr}")
    print(f"Username: {msg_obj['username']}")
    print(f"Password: {msg_obj['password']}")
    
    #Successful authentication
    if True:
        connection_socket.send(pickle.dumps({"status": True}))
        print(f"[SUCCESSFUL AUTHENTICATION] {addr}")
    else:
        connection_socket.send(pickle.dumps({"status": False}))
        print(f"[UNSUCCESSFULL AUTHENTICATION] {addr}")

def ued(connection_socket, addr, msg_obj):
    pass

def scs(connection_socket, addr, msg_obj):
    pass

def dte(connection_socket, addr, msg_obj):
    pass

def aed(connection_socket, addr, msg_obj):
    pass


def process_connection(connection_socket, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    while True:
        msg_raw = connection_socket.recv(MAX_SIZE)
        msg_obj = pickle.loads(msg_raw)
        
        
        if msg_obj["cmd"] == "auth":
            authenticate(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "UED":
            ued(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "SCS":
            scs(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "DTE":
            dte(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "AED":
            aed(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "OUT":
            print(f"[CLIENT REGQUESTED OUT] {addr}")
            break
    
    # will only break out of loop if out msg_obj is given
    connection_socket.close()
    print(f"[CONNECTION CLOSED] {addr} disconnected.")
        

def main():
    
    try:
        serverPort = int(sys.argv[1])
        authAttempts = int(sys.argv[2])
    except:
        print(f"Usage: {sys.argv[0]} <server-port-number: int> <authentication-attempt-number: int>")
        sys.exit(1)
    
    
    # create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    
    # bind socket to port number
    serverSocket.bind(('localhost', serverPort))
    
    # begin listening
    serverSocket.listen(2) 
    
    print(f"[LISTENING] Server Port: {serverPort}")
    while True:
        connection_socket, addr = serverSocket.accept()
        newThread = threading.Thread(target=process_connection, args = (connection_socket, addr))
        newThread.start()
        
    
if __name__ == "__main__":
    main()




"""
ERICS APPLICATION PROTOCOL

MESSAGE:
PICKLE ENCODED DICTIONARY
CONTAINS MINIMUM:
{
    "cmd":
    "Requied args":
    "Required data":
}

MAX SIZE 4096 INCL HEADERS

RESPONSES:
PICKLE ENCODED DICTIONARY
CONTAINS:
{
    "STATUS": True / False
}
"""



"""
msg_obj line arguments:
1: port
2: authentication attempt #
<port number> <login attempt number>

server will store:
dict mapping username to password (case sensitive)
    read from Credentials.txt in current directory
    space seperated text <username> <password>



steps
1: server will listen on a port specified at msg_obj line for client to connect
2: at connection establishment, client will send username and password
3: verify with server internal storage
4: given max of x attempts, after which block the client process for 10 seconds
5: after successful authentication, client will send msg_objs until connection termination
        Server logs timestance of the edge device in FILE edge-device-log.txt
        
        Active edge device sequence number; timestamp; edge device name; edge device IP address; edge device UDP server port number
        eg
        1; 30 September 2022 10:31:13; supersmartwatch; 129.64.31.13; 5432



msg_objs:
    EDG - Edge data generation
    UED - Upload edge data
    SCS - Server computation Service
    DTE - Delete data file
    AED - Active Edge Devices
    OUT - Exit Edge network

EDG - Edge data generation - client side

UED - Upload edge data

    Client send data samples through TCP
    Server adds to FILE upload-log.txt the following
        edgeDeviceName; timestamp; fileID; dataAmount
        eg
        supersmartwatch; 30 September 2022 10:31:13; 1; 10
    
    Note server needs to keep track of sent files for the scs msg_obj
    
SCS - Server computation Service
Server to perform computations on sent user files
if file does not exist on server, send prompt to client

computation operations:
SUM
AVERAGE
MAX
MIN

    Server will recieve request from client via tcp
    server find corresponding file => check for existance
    server will perform corresponding operations on file
    
DTE: Delete the data file

    Server will recieve request from client via tcp
    server find corresponding file => check for existance
    if exists, remove file
    add to log file deletion-log.txt
        edgeDeviceName; timestamp; fileID; dataAmount
        eg
        supersmartwatch; 30 September 2022 10:33:13; 1; 10
    return acknowledgement of success to client
    
AED: Active Edge Devices

    server will recieve request from client via tcp
    check for other active edge devices EXCLUDING client
    server should respond with:
        edge device names
        timestamps since the edge devices joined
        IP addresses
        Port Numbers
        
    If no other active clients:
        send "no other active edge devices"
        
    
           
"""