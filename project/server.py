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
import os
import shutil

MAX_SIZE = 4096

device_log_lock = threading.Lock()
upload_lock = threading.Lock()
delete_lock = threading.Lock()


#READ FROM CREDENTIALS.TXT FOR ACCOUNTS
def getFilePath(devicename, filename):
    return f"server_data/{devicename}/{filename}"



# writes data to given file path relative to current working directory
def log_active_connection(data: dict, ip_address: str):
    
    # logs stored as:
    # seq_num; timestamp; devicename; ip_address; port
    
    
    file_path = "logs/edge-device-log.txt"
    output_file = Path(file_path)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    
    timestamp = datetime.datetime.now().strftime("%d %B %Y %H:%M:%S")
    device = data["devicename"]
    udp_port = data["udp_port"]
    
    # get active device sequence number
    # mutex file read and write to avoid stale reads and corrupt writes
    device_log_lock.acquire()
    try:
        with open(file_path, 'r') as f:
            seq_num = len(f.readlines()) + 1
    except:
        seq_num = 1
    
    with open(file_path, 'a') as f:
        f.write(f"{seq_num}; {timestamp}; {device}; {ip_address}; {udp_port}\n")
    device_log_lock.release()
    
def remove_device_from_log(addr, msg_obj):
    file_path = "logs/edge-device-log.txt"
    tmp_file = "logs/edge-device-log-tmp.txt"
    
    device = msg_obj["devicename"]

    seq = 1
    device_log_lock.acquire()
    with open(tmp_file, "w") as tmp:
        with open(file_path, 'r') as log:
            for line in iter(log):
                data = line.split("; ")
                if device == data[2]:
                    continue
                data[0] = str(seq) 
                tmp.write("; ".join(data))
                seq += 1
    
    os.remove(file_path)
    os.rename(tmp_file, file_path)
    
    device_log_lock.release()
                
    
# writes data to given file path relative to current working directory
def log_file_update(data: dict, operation: str):
    """
    data must contain
    {
        "devicename": devicename,
        "fileID": fileID,
        "file_size": file_size
    }
    
    """
    
    file_path = f"logs/{operation}-log.txt"
    output_file = Path(file_path)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    
    device = data["devicename"]
    timestamp = datetime.datetime.now().strftime("%d %B %Y %H:%M:%S")
    fileID = data["fileID"]
    file_size = data["file_size"]

    # mutex file read and write to avoid stale reads and corrupt writes
    lock = upload_lock if operation == "update" else delete_lock
    lock.acquire()
    with open(file_path, 'a') as f:
        f.write(f"{device}; {timestamp}; {fileID}; {file_size}\n")
    lock.release()
    

# Returns true if client connection is allowed to persist
# Returns false if client connection is blocked
# blocks account name
#IF GIVEN INVALID ACCOUNT NAME, PROMPT TO RETRY INDEFINATELY

def authenticate(connection_socket, addr, msg_obj):
    devicename = msg_obj['devicename']
    password = msg_obj['password']
    
    print(f"[AUTHENTICATION REQUEST] {addr}")
    print(f"Devicename: {devicename}")
    print(f"Password: {password}")
    
    
    # Device name does not exist on server
    if devicename not in database:
        connection_socket.send(pickle.dumps({"status": 401}))
        print(f"[UNKNOWN DEVICE] {addr}")
        return True
    
    # if edge device exceeded login attempts 
    if database[devicename]["login_attempts"] >= authAttempts:
        
        # if connection still blocked, terminate
        if (datetime.datetime.now() - database[devicename]["last-attempted"]).seconds < 10:
            connection_socket.send(pickle.dumps({"status": 418}))
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
            connection_socket.send(pickle.dumps({"status": 418}))
            return False
        
        connection_socket.send(pickle.dumps({"status": 403}))
        print(f"[UNSUCCESSFULL AUTHENTICATION] {addr}")

    # update last accessed
    database[devicename]["last-attempted"] = datetime.datetime.now()
    return True

def ued(connection_socket, addr, msg_obj):

    print(f"[UED] {addr}")
    print(f"Downloading file: {msg_obj['file_name']}...")
    
    file_path = getFilePath(msg_obj['devicename'], msg_obj['file_name'])
    downloaded_file = Path(file_path)
    downloaded_file.parent.mkdir(exist_ok=True, parents=True)    
    
    with open(file_path, "wb") as f:
        for _ in range(int(msg_obj["segments"])):
            data = connection_socket.recv(MAX_SIZE)
            f.write(data)
    
    log_file_update(msg_obj, "upload")
    print(f"Downloaded file: {msg_obj['file_name']} {msg_obj['file_size']} bytes")
    connection_socket.send(pickle.dumps({"status": 200}))

def scs(connection_socket, addr, msg_obj):
    
    print(f"[SCS] {addr} requesting {msg_obj['computation']}({msg_obj['file_name']})")
    
    try:
        file_path = getFilePath(msg_obj['devicename'], msg_obj['file_name'])
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
    
    
    file_name = f"{msg_obj['devicename']}-{msg_obj['fileID']}.txt"
    print(f"[DTE] {addr} {file_name}")
    
    file_path = getFilePath(msg_obj['devicename'], file_name)

    try: 
        with open(file_path, 'r') as f:
            file_size = len(f.readlines())
        
        os.remove(file_path)
        
    # file doesnt exist
    except:
        connection_socket.send(pickle.dumps({"status": 400}))
        print(f"Failed to delete file {file_name}. File not found.")
        return
    
    msg_obj['file_size'] = file_size
    log_file_update(msg_obj, "deletion")
    print(f"Successfully deleted {file_name}.")
    
    connection_socket.send(pickle.dumps({"status": 200}))

def aed(connection_socket, addr, msg_obj):
    
    print(f"[AED] {addr}")
    devicename = msg_obj['devicename']
    file_path = "logs/edge-device-log.txt"

    data = []
    status = 404
    device_log_lock.acquire()
    try:
        with open(file_path, 'r') as f:
            data = [line.split("; ") for line in f.readlines()]
    except:
        status = 400
    device_log_lock.release()
    
    # [{device: devicename, addr: ip_address, port: port, timestamp: timestamp}]
    msg = {}
    for device in data:
        if devicename != device[2]:
            msg[device[2]] = {
                "timestamp": device[1],
                "device": device[2],
                "addr": device[3],
                "port": device[4].strip()
            }
    
    # set success status
    if msg and status != 400:
        status = 200
    
    connection_socket.send(pickle.dumps({"status": status, "msg": msg}))
    

# TODO send acknowledgement after removing from edge devices log
def out(connection_socket, addr, msg_obj):
    print(f"[CLIENT REGQUESTED OUT] {addr}")
    remove_device_from_log(addr, msg_obj)
    connection_socket.send(pickle.dumps({"status": 200}))
    

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
        

# when server starts, delete existing logs
# network is empty at startup = no logs, no files, no connected devices
def main():
    global database
    global authAttempts
    try:
        serverPort = int(sys.argv[1])
        authAttempts = int(sys.argv[2])
    except:
        print(f"Usage: {sys.argv[0]} <server-port-number: int [1024 - 65535]> <allowed-authentication-attempts: int [1 - 5]>")
        sys.exit(1)
    
    
    # clear all prev logs:
    try:
        shutil.rmtree('logs')
    except:
        pass
    
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
    
    serverSocket.close()  
    
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
        edgeDeviceName; timestamp; fileID; file_size
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
        edgeDeviceName; timestamp; fileID; file_size
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