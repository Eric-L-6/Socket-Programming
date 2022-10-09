#! /usr/bin/env python3 


from socket import *
from collections import defaultdict
from statistics import mean
from pathlib import Path
import pickle

import platform
import threading
import datetime
import sys

MAX_SIZE = 4096

lock = threading.Lock()


#READ FROM CREDENTIALS.TXT FOR ACCOUNTS


# writes data to given file path relative to current working directory
def log_active_connection(data: dict, ip_address: str):
    
    file_path = "logs/edge-device-log.txt"
    output_file = Path(file_path)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    
    timestamp = datetime.datetime.now().strftime("%d %B %Y %H:%M:%S")
    device = data["devicename"]
    udp_port = data["udp_port"]
    
    # get active device sequence number
    # mutex file read and write to avoid stale reads and corrupt writes
    lock.acquire()
    try:
        with open(file_path, 'r') as f:
            seq_num = len(f.readlines()) + 1
    except:
        seq_num = 1
    
    with open(file_path, 'a') as f:
        f.write(f"{seq_num}; {timestamp}; {device}; {ip_address}; {udp_port}\n")
    lock.release()
    
# writes data to given file path relative to current working directory
def log_file_upload(data: dict):
    
    file_path = "logs/upload-log.txt"
    output_file = Path(file_path)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    
    device = data["devicename"]
    timestamp = datetime.datetime.now().strftime("%d %B %Y %H:%M:%S")
    fileID = data["fileID"]
    dataAmount = data["dataAmount"]

    # mutex file read and write to avoid stale reads and corrupt writes
    lock.acquire()
    with open(file_path, 'a') as f:
        f.write(f"{device}; {timestamp}; {fileID}; {dataAmount}\n")
    lock.release()


# Returns true if client connection is allowed
# Returns false if client connection is blocked
def authenticate(connection_socket, addr, msg_obj):
    devicename = msg_obj['devicename']
    password = msg_obj['password']
    
    print(f"[AUTHENTICATION REQUEST] {addr}")
    print(f"Devicename: {devicename}")
    print(f"Password: {password}")
    
    
    # if edge device exceeded login attempts 
    if database[devicename]["login_attempts"] >= authAttempts:
        
        # if connection still blocked, terminate
        if (datetime.datetime.now() - database[devicename]["last-attempted"]).seconds < 10:
            connection_socket.send(pickle.dumps({"status": 404}))
            return False
        
        # reset login attemps
        else:
            database[devicename]["login_attempts"] = 0
        
    
    #Successful authentication
    if database[devicename]["pwd"] == password:
        database[devicename]["login_attempts"] = 0
        connection_socket.send(pickle.dumps({"status": 200}))
        print(f"[SUCCESSFUL AUTHENTICATION] {addr}")
        
        log_active_connection(msg_obj, addr[0])
        
        
    # unsucessfull authentication 
    else:
        database[devicename]["login_attempts"] += 1
        
        if database[devicename]["login_attempts"] >= authAttempts:
            connection_socket.send(pickle.dumps({"status": 404}))
            return False
        
        connection_socket.send(pickle.dumps({"status": 400}))
        print(f"[UNSUCCESSFULL AUTHENTICATION] {addr}")

    # update last accessed
    database[devicename]["last-attempted"] = datetime.datetime.now()
    return True

# TODO handle larger files
def ued(connection_socket, addr, msg_obj):

    print(f"[UED] {addr}")
    print(f"Recieved file: {msg_obj['file_name']} (size {msg_obj['dataAmount']})")
    
    file_path = f"user_data/{msg_obj['devicename']}/{msg_obj['file_name']}"
    downloaded_file = Path(file_path)
    downloaded_file.parent.mkdir(exist_ok=True, parents=True)    
    downloaded_file.write_text(msg_obj["data"])
    log_file_upload(msg_obj)
    
    connection_socket.send(pickle.dumps({"status": 200}))
    
    
        
    
def scs(connection_socket, addr, msg_obj):
    
    print(f"[SCS] {addr} requesting {msg_obj['computation']}({msg_obj['file_name']})")
    
    try:
        file_path = f"user_data/{msg_obj['devicename']}/{msg_obj['file_name']}"
        print(file_path)
        with open(file_path, "r") as f: 
            data = list(map(lambda num : int(num), f.readlines()))
        
        if msg_obj['computation'] == 'SUM':
            result = sum(data)
        elif msg_obj['computation'] == 'AVERAGE':
            result = mean(data)
        elif msg_obj['computation'] == 'MAX':
            result = max(data)
        elif msg_obj['computation'] == 'MIN':
            result = min(data)
        
        connection_socket.send(pickle.dumps({
            "status": 200,
            "result": result
        }))
        
    except:
        connection_socket.send(pickle.dumps({
            "status": 400,
        }))


def dte(connection_socket, addr, msg_obj):
    pass

def aed(connection_socket, addr, msg_obj):
    pass


# TODO send acknowledgement after removing from edge devices log
def out(connection_socket, addr, msg_obj):
    print(f"[CLIENT REGQUESTED OUT] {addr}")
    

def process_connection(connection_socket, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    while True:
        msg_raw = connection_socket.recv(MAX_SIZE)
        msg_obj = pickle.loads(msg_raw)
        
        
        if msg_obj["cmd"] == "AUTH":
            if not authenticate(connection_socket, addr, msg_obj):
                print(f"[EXCEEDED AUTHENTICATION ATTEMPT LIMIT] {addr}.")
                break
        elif msg_obj["cmd"] == "UED":
            ued(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "SCS":
            scs(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "DTE":
            dte(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "AED":
            aed(connection_socket, addr, msg_obj)
        elif msg_obj["cmd"] == "OUT":
            out(connection_socket, addr, msg_obj)
            break
    
    # will only break out of loop if out command is given or authentication exceeds login_attempts
    connection_socket.close()
    print(f"[CONNECTION CLOSED] {addr} disconnected.")
        

def main():
    global database
    global authAttempts
    try:
        serverPort = int(sys.argv[1])
        authAttempts = int(sys.argv[2])
    except:
        print(f"Usage: {sys.argv[0]} <server-port-number: int> <authentication-attempt-number: int>")
        sys.exit(1)
    
    # load credentials from credentials.txt
    database = defaultdict(lambda: defaultdict(int))
    with open("credentials.txt", "r") as accounts:
        while account := accounts.readline():
            devicename, password = account.split(" ")
            database[devicename.strip()]["pwd"] = password.strip()
            database[devicename.strip()]["login-attemps"] = 0
            database[devicename.strip()]["last-attempted"] = datetime.datetime.now() - datetime.timedelta(seconds=10)

    
    # create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    
    # bind socket to port number
    serverSocket.bind(('localhost', serverPort))
    
    # begin listening
    serverSocket.listen(2) 
    
    print(f"[LISTENING] Server Port: {serverPort}")
    
    try:
        while True:
            connection_socket, addr = serverSocket.accept()
            newThread = threading.Thread(target=process_connection, args = (connection_socket, addr))
            newThread.start()
    except KeyboardInterrupt:
        print("\nTerminating Server")
        return  
    
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
Database contains:

{
    "devicename": {
        "pwd": password,
        "login-attempts": int,
        "last-attempted": datetime
    }
}

"""



"""
msg_obj line arguments:
1: port
2: authentication attempt #
<port number> <login attempt number>

server will store:
dict mapping devicename to password (case sensitive)
    read from Credentials.txt in current directory
    space seperated text <devicename> <password>



steps
1: server will listen on a port specified at msg_obj line for client to connect
2: at connection establishment, client will send devicename and password
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