#! /usr/bin/env python3 

from socket import *
from pathlib import Path


import multiprocessing
import threading
import pickle
import random
import time
import sys
import re
import os
import math
    
MAX_SIZE = 4096
    
class P2PClient():
    
    
    def __init__(self, serverIp, serverPort, p2pUDPPort):
        self.serverIp = serverIp
        self.serverPort = serverPort
        self.p2pUDPPort = p2pUDPPort
        self.devicename = "guest"
        self.peers = {}
        
        # create TCP connection
        self.clientSocket = socket(AF_INET, SOCK_STREAM)
        self.clientSocket.connect((self.serverIp, self.serverPort))
        self.isConnected = False
    
        # create udp socket
        self.udpListeningSocket = socket(AF_INET, SOCK_DGRAM)
        self.udpListeningSocket.bind(('', p2pUDPPort))
        self.udpListenSubProcess = multiprocessing.Process(target=self._udp_listen)
        self.uvfThreads= []
        self.recvThreads = []
        
    
    #
    def authenticate(self):
        
        self.devicename = input("Devicename: ").strip()
        
        while True:
            password = input("Password: ").strip()
            msg = pickle.dumps({"cmd": "AUTH", "devicename": self.devicename, "password": password, "udp_port": self.p2pUDPPort})
            if sys.getsizeof(msg) >= MAX_SIZE:
                print("[ERROR] Password and Device name is too large.")
                continue
            
            self.clientSocket.send(msg)
            
            reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
            
            # successful authentication
            if reply["status"] == 200:
                self.isConnected = True
                return
            
            # unauthorized. Client unknown
            if reply["status"] == 401:
                print(f"The device '{self.devicename}' is not recognised. Please login with a different device.")
                self.devicename = input("Devicename: ").strip()
                continue
            
            # unauthorized. CLient known
            elif reply["status"] == 403:
                print("Incorrect password. Please try again.")
            
            # teapot does not serve potential scammers
            elif reply["status"] == 418:
                print("Number of attempts exceeded. Your account has been blocked. Please ty again later.")
                sys.exit(0)
        
    
    # generate file with list of integers of given length
    def edg(self, command):
        
        try:
            fileID = int(command[1])
            dataAmount = int(command[2])
        except:
            print("EDG Usage: EDG <fileID: int> <dataAmount: int>")
            return
        
        
        file_path = f"client_data/{self.devicename}-{fileID}.txt"
        output_file = Path(file_path)
        output_file.parent.mkdir(exist_ok=True, parents=True)
        
        with open(file_path, "w") as f:
            for _ in range(dataAmount):
                f.write(str(random.randint(0, dataAmount)) + "\n")

        print(f"[EDG] Written {dataAmount} integers into {file_path}")
        

    def ued(self, command):
        
        # process args
        try:
            fileID = int(command[1])
        except:
            print("[UED] Usage: UED <fileID: int>")
            return
        
        file_name = f"{self.devicename}-{fileID}.txt"
        file_path = f"client_data/{self.devicename}-{fileID}.txt"
        
        header = {
            "cmd": "UED", 
            "devicename": self.devicename, 
            "file_name": file_name,
            "fileID": fileID,
        }
        
        try:
            file_size = os.stat(file_path).st_size
            header["file_size"] = file_size
            header["segments"] = math.ceil(file_size / MAX_SIZE)
            self.clientSocket.send(pickle.dumps(header))
            
            #send file as binary segments
            with open(file_path, "rb") as f:
                while buffer := f.read(MAX_SIZE):
                    self.clientSocket.send(buffer)
            
        except:
            print(f"UED Error: {file_name} does not exist")
            return


        reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
            
        # successful authentication
        if reply["status"] == 200:
            print(f"[UED] Uploaded {file_name}")
        
        else:
            print(f"[UED] Failed to upload {file_name}")

    
    def scs(self, command):
        
         # process args
        try:
            fileID = int(command[1])
            computation = command[2].upper()
        except:
            print("[SCS] Usage: SCS <fileID: int> <computationOperation>")
            return
        
        if computation not in {'SUM', 'AVERAGE', 'MAX', 'MIN'}:
            print("[SCS] Supported computations: SUM, AVERAGE, MAX, MIN.")
            return
        
        file_name = f"{self.devicename}-{fileID}.txt"
        
        # send message
        self.clientSocket.send(pickle.dumps({
            "cmd": "SCS",
            "file_name": file_name,
            "devicename": self.devicename,
            "computation": computation
        }))
        
        try:
            reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
                
            # successful authentication
            if reply["status"] == 200:
                print(f"[SCS] {computation}({file_name}) = {reply['result']}")
            
            elif reply["status"] == 400:
                print(f"[SCS] error: {file_name} has not been uploaded to the server.")

            else:
                raise Exception()
        except:
            print(f"[SCS] error: Failed to compute {computation}({file_name})")

    
    def dte(self, command):
         # process args
        try:
            fileID = int(command[1])
        except:
            print("[DTE] Usage: DTE <fileID: int>")
            return
        
        file_name = f"{self.devicename}-{fileID}.txt"
        
        # send message
        self.clientSocket.send(pickle.dumps({
            "cmd": "DTE",
            "devicename": self.devicename,
            "fileID": fileID
        }))
        
        reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
        
        if reply["status"] == 200:
            print(f"[DTE] Sucessfully deleted {file_name} from server.")
        
        elif reply["status"] == 400:
            print(f"[DTE] error: {file_name} does not exist on server.")
        
      
    
    def aed(self, display=True):
        
        # send aed request       
        self.clientSocket.send(pickle.dumps({"cmd": "AED", "devicename": self.devicename}))

        # process reply
        reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))

        # update internal cache of peers
        self.peers = reply["msg"]
        if not display:
            return

        if reply["status"] == 200:
            for msg in reply["msg"].values():
                print(f"[{msg['device']}] listening on {msg['addr']}:{msg['port']}. Active since {msg['timestamp']}.")
            
        elif reply["status"] == 400:
            print(f"[AED] Server: No other active edge devices.")
            
        elif reply["status"] == 404:
            print(f"[AED] Error: cannot determine active edge devices.")
        
        

    
    def out(self, command):
        self.clientSocket.send(pickle.dumps({"cmd": "OUT", "devicename": self.devicename}))
        
        # process reply
        reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
        
        if reply["status"] == 200:
            print("[OUT] Successfully logged out.")
            print("Closing terminal...")
            self.clientSocket.close()
            self.udpListenSubProcess.terminate()
            for thread in self.uvfThreads:
                thread.join()
            for thread in self.recvThreads:
                thread.join()
            self.isConnected = False
            return True
        
        else:
            print(f"[OUT] Error: Unable to log out.")
            return False
    
    def getHelp(self):
        print("""Available commands
    EDG - Edge data generation
    UED - Upload edge data
    SCS - Server computation Service
    DTE - Delete data file
    AED - Active Edge Devices
    OUT - Exit Edge network
    """)
        
    def _uvf_send(self, target_device, target_addr, target_port, file_name):
        
        print(f"UVF Command sending {file_name} to {target_device} at {target_addr} {target_port}")
        
        # create new socket
        udp_socket = socket(AF_INET, SOCK_DGRAM)
        
        header = {
            "cmd": "UVF",
            "device_name": self.devicename,
            "file_name": re.search('[^\/]*$', file_name).group(0),
        }
    
        try:
            file_size = os.stat(file_name).st_size
            header["file_size"] = file_size
            header["segments"] = math.ceil(file_size / MAX_SIZE)
        except:
            print(f"[UVF] Error: {file_name} does not exist")
            self.uvfThreads.remove(threading.current_thread()) 
            return

        print(f"sending to {target_addr} {target_port} {target_device}")
        print(header)
        
        # send header
        udp_socket.sendto(pickle.dumps(header), (target_addr, target_port))
        
        # recieve confirmation + new dest recieving port
        reply, new_addr = udp_socket.recvfrom(MAX_SIZE)     
        reply = pickle.loads(reply)
        
        udp_socket.sendto(pickle.dumps(reply), new_addr)
        
        print("Reply")
        print(reply)
        
        if reply["status"] == 200:
            #send file as binary segments
            with open(file_name, "rb") as f:
                segment = 0
                while buffer := f.read(MAX_SIZE):
                    udp_socket.sendto(buffer, new_addr)
                    reply = pickle.loads(udp_socket.recv(MAX_SIZE))
                    if reply["ack"] != segment:
                        print("[UVF] Error: packet Loss]")
                        print(f"Sent {segment - 1}/{header['segments']} packets. ")
                        return
                    segment += 1
        
        else:
            print("[UVF] Error: Failed to send {file_name} to {target_device}.")
    
            
        print(f"\nUVF Command {file_name} sent to {target_device} at {new_addr}")
        if self.isConnected:
            print("Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT, HELP): ", end = '', flush=True)
        
        # clean up thread references
        self.uvfThreads.remove(threading.current_thread()) 
 
    def uvf(self, command):

        #process args
        try:
            target_device = command[1]
            file_name = command[2]
        except:
            print("[UVF] Usage: UVF <deviceName: str> <file_name: str>")
            return

        if target_device == self.devicename:
            print("[UVF] Error: cannot send file to own device")
            return

        # update internal cache of peers
        self.aed(display=False)

        if target_device not in self.peers:
            print(f"[UVF] Error: {target_device} is not currently active.")
            return
        else:
            target_addr = self.peers[target_device]["addr"]
            target_port = int(self.peers[target_device]["port"])

        # open new thread to send file
        uvf_thread = threading.Thread(target=self._uvf_send, args = [target_device, target_addr, target_port, file_name])
        self.uvfThreads.append(uvf_thread)
        uvf_thread.start()


    def _udp_recv(self, msg_obj, senderAddr):
        
        # create new udp socket to recv file
        recv_socket = socket(AF_INET, SOCK_DGRAM)
        
        print("recieving file")
        print(msg_obj)
        recv_socket.sendto(pickle.dumps({"status": 200}), senderAddr)

        ack = recv_socket.recv(MAX_SIZE)
        print(pickle.loads(ack))


        file_path = f"{msg_obj['device_name']}/{msg_obj['file_name']}"
        downloaded_file = Path(file_path)
        downloaded_file.parent.mkdir(exist_ok=True, parents=True)    
    
        with open(file_path, "wb") as f:
            for segment in range(int(msg_obj["segments"])):
                data = recv_socket.recv(MAX_SIZE)
                f.write(data)
                recv_socket.sendto(pickle.dumps({"ack": segment}), senderAddr)
        
        
        
        print(f"Recieved {msg_obj['file_name']} from {msg_obj['device_name']}")
        # repeat default message
        print("Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT, HELP): ", end = '', flush=True)
        self.recvThreads.remove(threading.current_thread()) 
    

    # continuously run in seperate thread
    def _udp_listen(self):
        while self.isConnected:
            data, senderAddr = self.udpListeningSocket.recvfrom(MAX_SIZE)
            data = pickle.loads(data)
            recv_thread = threading.Thread(target=self._udp_recv, args = (data, senderAddr))
            self.recvThreads.append(recv_thread)
            recv_thread.start()            


    def udp_listen(self):
        # begin listening
        print("listening...")
        self.udpListenSubProcess.start()

"""
UDP source sends packet to UDP dest 
including: filename, file_size,
UDP dest sends ack to source with NEW UDP SOCKET + port running on seperate thread
UDP source then sends subsequent packets of file to the new UDP socket at dest
og dest UDP socket continues to listen

"""
        

# OS chooses the port to send UDP data to
# client udp port: port that will be used to ONLY RECIEVE DATA
#thus client with have TWO UDP SOCKETS
def main():
    
    try:
        serverIp = sys.argv[1]
        serverPort = int(sys.argv[2])
        p2pUDPPort = int(sys.argv[3])
    except:
        print(f"Usage: {sys.argv[0]} <server-ip-address> <server-port-number: int> <P2P-UDP-server-port-number: int [1024 - 65535]>")
        sys.exit(1)
    
    try:
        client = P2PClient(serverIp, serverPort, p2pUDPPort)
    except:
        print(f"Error: No server found at {serverIp}:{serverPort}")
        return
    
    
    client.authenticate()
    client.udp_listen()
    print("Welcome!")
    
    while user_input := input("Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT, HELP): "):
        
        command = user_input.split()
        
        if command[0].upper() == "EDG":
            client.edg(command)
        elif command[0].upper() == "UED":
            client.ued(command)
        elif command[0].upper() == "SCS":
            client.scs(command)
        elif command[0].upper() == "DTE":
            client.dte(command)
        elif command[0].upper() == "AED":
            client.aed()
        elif command[0].upper() == "OUT":
            if client.out(command):
                break
        elif command[0].upper() == "UVF":
            client.uvf(command)
        elif command[0].upper() == "HELP":
            client.getHelp()
        else:
            print("[ERROR] Unknown command: " + command[0])
            
    print(f"Bye, {client.devicename}!")

if __name__ == "__main__":
    main()
    

    

    

"""
command line arguments:
1: server ip address
2: server port number
3: client UDP port number
<server ip address> <server port number> <client port number>


steps
1 client initiate TCP connection with server at specified port
2: upon connection establishment, initiate authentication processes:
    user input devicename
    user input password
    send tcp segment to server
    server sends success or failure
    
Upon failure:
    User prompted to retry input
    After several consecutive failed inputs, number specified at server and thus stored at server
    edge device is blocked for 10 seconds (can be serverside or clientside)
    
    
Upon success:
    client sends the server the UDP port number that will listen for p2p connections

Available commands
    EDG - Edge data generation
    UED - Upload edge data
    SCS - Server computation Service
    DTE - Delete data file
    AED - Active Edge Devices
    OUT - Exit Edge network

EDG - Edge data generation 
input: 'EDG' <fileId: int> <dataAmount: int>
Need to check for correct input


fileId: unique identifier for file 
    if file already exists, simply overwrite the existing data


dataAmount: number of data samples to be generated
    Data samples:
        each datasample can be a randomly generated integer
        For example dataAmount = 10, randomly generate 10 integers and store in 
        created file
        Store one integer per line

Resulting file_path:
device name - fileId . txt
eg
supersmartwatch-1.txt

print acknowledgement of completion

UED - Upload edge data
input: 'UED' <fileID: int>
Need to check for correct input
Need to check if file exists

    Client will read the data in the specified file and ransfer the data samples to the
    central server using TCP

    upon recieving acknowledgement from server, print acknowledgement of completion

SCS - Server computation Service
input: 'SCS' <fileID: int> <computationOperation>
prompt user for correct input

allowed input operations:
SUM, AVERAGE, MAX, MIN

prompt user for allowed input operations
Send to server
print output from server

DTE: Delete the data file
Input: 'DTE' fileID

prompt for correct input
send message to server
if failure
prompt user file does not exist
else 
prompt user of success

AED: Active Edge Devices
Input: 'AED'
no other arguments

    send request to server
    print response from server


OUT - Exit Edge network
Input: 'OUT'
no other arguments

    Client to close TCP connection
    Exit with goodby message at terminal

"""