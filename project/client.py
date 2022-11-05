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
    
    
    def __init__(self, server_ip, server_port, p2p_udp_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.p2p_udp_port = p2p_udp_port
        self.devicename = "guest"
        self.peers = {}
        
        # create TCP connection
        self.client_socket = socket(AF_INET, SOCK_STREAM)
        self.client_socket.connect((self.server_ip, self.server_port))
        self.is_connected = False
    
        # create udp socket
        self.udp_listening_socket = socket(AF_INET, SOCK_DGRAM)
        self.udp_listening_socket.bind(('', p2p_udp_port))
        self.udp_listen_subprocess = multiprocessing.Process(target=self._udp_listen)
        self.uvf_threads= []
        self.recv_threads = []
        
    
    #
    def authenticate(self):
        
        self.devicename = input("Devicename: ").strip()
        
        while True:
            password = input("Password: ").strip()
            msg = pickle.dumps({"cmd": "AUTH", "devicename": self.devicename, "password": password, "udp_port": self.p2p_udp_port})
            if sys.getsizeof(msg) >= MAX_SIZE:
                print("[ERROR] Password and Device name is too large.")
                continue
            
            self.client_socket.send(msg)
            
            reply = pickle.loads(self.client_socket.recv(MAX_SIZE))
            
            # successful authentication
            if reply["status"] == 200:
                self.is_connected = True
                return
            
            # unauthorized. Client unknown
            if reply["status"] == 401:
                print(f"The device '{self.devicename}' is not recognised. Please login with a different device.")
                self.devicename = input("Devicename: ").strip()
                continue
            
            # unauthorized. CLient known
            elif reply["status"] == 403:
                print("Incorrect password. Please try again.")
            
            # Blocked from multiple authentication failures.
            elif reply["status"] == 418:
                print("Number of attempts exceeded. Your account has been blocked. Please ty again later.")
                sys.exit(0)
        
    
    # generate file with list of integers of given length
    def edg(self, command):
        
        try:
            fileID = int(command[1])
            data_amount = int(command[2])
        except:
            print("EDG Usage: EDG <fileID: int> <data_amount: int>")
            return
        
        
        file_path = f"client_data/{self.devicename}-{fileID}.txt"
        output_file = Path(file_path)
        output_file.parent.mkdir(exist_ok=True, parents=True)
        
        with open(file_path, "w") as f:
            for _ in range(data_amount):
                f.write(str(random.randint(0, data_amount)) + "\n")

        print(f"[EDG] Written {data_amount} integers into {file_path}")
        

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
            self.client_socket.send(pickle.dumps(header))
            
            #send file as binary segments
            with open(file_path, "rb") as f:
                while buffer := f.read(MAX_SIZE):
                    self.client_socket.send(buffer)
            
        except:
            print(f"UED Error: {file_name} does not exist")
            return


        reply = pickle.loads(self.client_socket.recv(MAX_SIZE))
            
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
        self.client_socket.send(pickle.dumps({
            "cmd": "SCS",
            "devicename": self.devicename,
            "file_name": file_name,
            "computation": computation
        }))
        
        try:
            reply = pickle.loads(self.client_socket.recv(MAX_SIZE))
                
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
        self.client_socket.send(pickle.dumps({
            "cmd": "DTE",
            "devicename": self.devicename,
            "fileID": fileID
        }))
        
        reply = pickle.loads(self.client_socket.recv(MAX_SIZE))
        
        if reply["status"] == 200:
            print(f"[DTE] Sucessfully deleted {file_name} from server.")
        
        elif reply["status"] == 400:
            print(f"[DTE] error: {file_name} does not exist on server.")
        
      
    
    def aed(self, display=True):
        
        # send aed request       
        self.client_socket.send(pickle.dumps({"cmd": "AED", "devicename": self.devicename}))

        # process reply
        reply = pickle.loads(self.client_socket.recv(MAX_SIZE))

        # update internal cache of peers
        self.peers = reply["result"]
        if not display:
            return

        if reply["status"] == 200:
            for res in reply["result"].values():
                print(f"[{res['device']}] listening on {res['addr']}:{res['port']}. Active since {res['timestamp']}.")
            
        elif reply["status"] == 404:
            print(f"[AED] Server: No other active edge devices.")
            
        elif reply["status"] == 400:
            print(f"[AED] Error: cannot determine active edge devices.")
        
    
    def out(self, command):
        self.client_socket.send(pickle.dumps({"cmd": "OUT", "devicename": self.devicename}))
        
        # process reply
        reply = pickle.loads(self.client_socket.recv(MAX_SIZE))
        
        if reply["status"] == 200:
            print("[OUT] Successfully logged out.")
            print("Closing terminal...")
            self.client_socket.close()
            self.udp_listen_subprocess.terminate()
            for thread in self.uvf_threads:
                thread.join()
            for thread in self.recv_threads:
                thread.join()
            self.is_connected = False
            return True
        
        else:
            print(f"[OUT] Error: Unable to log out.")
            return False
    
    def get_help(self):
        print("""Available commands
    EDG - Edge data generation
    UED - Upload edge data
    SCS - Server computation Service
    DTE - Delete data file
    AED - Active Edge Devices
    OUT - Exit Edge network
    """)

    ############################## P2P Functionality ################################
    

    def _terminate_uvf(self):
        if self.is_connected:
            print("Enter one of the following commands (EDG, UED, SCS, DTE, AED, OUT, HELP): ", end = '', flush=True)
        self.uvf_threads.remove(threading.current_thread()) 
        return
        
    def _uvf_send(self, target_device, target_addr, target_port, file_path):
        
        file_name = re.search('[^\/]*$', file_path).group(0)
        
        
        # create new socket
        udp_socket = socket(AF_INET, SOCK_DGRAM)
        
        header = {
            "cmd": "UVF",
            "device_name": self.devicename,
            "file_name": file_name,
        }

        try:
            file_size = os.stat(file_path).st_size
            header["file_size"] = file_size
            header["segments"] = math.ceil(file_size / MAX_SIZE)
        except:
            print(f"\n[UVF] Error: {file_name} does not exist")
            self._terminate_uvf()
            return
        
        # send header
        udp_socket.sendto(pickle.dumps(header), (target_addr, target_port))
        
        # recieve confirmation + new dest recieving port
        reply, new_addr = udp_socket.recvfrom(MAX_SIZE)     
        reply = pickle.loads(reply)
        
        udp_socket.sendto(pickle.dumps(reply), new_addr)
        
        
        if reply["status"] == 200:
            
            print(f"\n[UVF]: Sending {file_name} to {target_device} at {target_addr} {target_port}...")
            
            #send file as binary segments
            with open(file_path, "rb") as f:
                segment = 0
                while buffer := f.read(MAX_SIZE):
                    udp_socket.sendto(buffer, new_addr)
                    reply = pickle.loads(udp_socket.recv(MAX_SIZE))
                    if reply["ack"] != segment:
                        print("[UVF] Error: packet Loss]")
                        print(f"Sent {segment - 1}/{header['segments']} packets.")
                        self._terminate_uvf()
                        return
                    segment += 1
        
        else:
            print("[UVF] Error: Failed to send {file_name} to {target_device}.")
            self._terminate_uvf()
    
            
        print(f"[UVF]: {file_name} sent to {target_device} at {new_addr}")
        self._terminate_uvf()
 
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
        self.uvf_threads.append(uvf_thread)
        uvf_thread.start()


    def _udp_recv(self, msg_obj, senderAddr):
        
        # create new udp socket to recv file
        recv_socket = socket(AF_INET, SOCK_DGRAM)
        
        print("\nRecieving file...")
        recv_socket.sendto(pickle.dumps({"status": 200}), senderAddr)

        ack = recv_socket.recv(MAX_SIZE)


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
        self.recv_threads.remove(threading.current_thread()) 
    

    # continuously run in seperate thread
    def _udp_listen(self):
        while self.is_connected:
            data, senderAddr = self.udp_listening_socket.recvfrom(MAX_SIZE)
            data = pickle.loads(data)
            recv_thread = threading.Thread(target=self._udp_recv, args = (data, senderAddr))
            self.recv_threads.append(recv_thread)
            recv_thread.start()            


    def udp_listen(self):
        # begin listening
        print("listening...")
        self.udp_listen_subprocess.start()

r
        

# OS chooses the port to send UDP data to
# client udp port: port that will be used to ONLY RECIEVE DATA
#thus client with have TWO UDP SOCKETS
def main():
    
    try:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        p2p_udp_port = int(sys.argv[3])
    except:
        print(f"Usage: {sys.argv[0]} <server-ip-address> <server-port-number: int> <P2P-UDP-server-port-number: int [1024 - 65535]>")
        sys.exit(1)
    
    try:
        client = P2PClient(server_ip, server_port, p2p_udp_port)
    except:
        print(f"Error: No server found at {server_ip}:{server_port} or UDP port {p2p_udp_port} is currently being used.")
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
            client.get_help()
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
input: 'EDG' <fileId: int> <data_amount: int>
Need to check for correct input


fileId: unique identifier for file 
    if file already exists, simply overwrite the existing data


data_amount: number of data samples to be generated
    Data samples:
        each datasample can be a randomly generated integer
        For example data_amount = 10, randomly generate 10 integers and store in 
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