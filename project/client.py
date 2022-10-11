#! /usr/bin/env python3 

from socket import *
from pathlib import Path
import pickle
import pickle
import random
import sys
    
MAX_SIZE = 4096
    
class P2PClient():
    
    
    def __init__(self, serverIp, serverPort, p2pUDPPort):
        self.serverIp = serverIp
        self.serverPort = serverPort
        self.p2pUDPPort = p2pUDPPort
        self.devicename = "guest"
        
        # create TCP connection
        self.clientSocket = socket(AF_INET, SOCK_STREAM)
        self.clientSocket.connect((self.serverIp, self.serverPort))
    
        
    
    def authenticate(self):
        
        self.devicename = input("Devicename: ").strip()
        while True:
            password = input("Password: ").strip()

            msg = pickle.dumps({"cmd": "AUTH", "devicename": self.devicename, "password": password, "udp_port": self.p2pUDPPort})
            self.clientSocket.send(msg)
            
            reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
            
            # successful authentication
            if reply["status"] == 200:
                return
            
            elif reply["status"] == 400:
                print("Incorrect devicename or password. Please try again.")
                
            elif reply["status"] == 404:
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
        
        data = ""
        for _ in range(dataAmount):
            data = data + str(random.randint(0, dataAmount)) + "\n"
            
        output_file.write_text(data)
        print(f"[EDG] Written {dataAmount} integers into {file_path}")

    #TODO: manage arge files by splitting into chunks
    def ued(self, command):
        
        # process args
        try:
            fileID = int(command[1])
        except:
            print("[UED] Usage: UED <fileID: int>")
            return
        
        file_name = f"{self.devicename}-{fileID}.txt"
        file_path = f"client_data/{self.devicename}-{fileID}.txt"
        
        msg_packet = {
            "cmd": "UED", 
            "devicename": self.devicename, 
            "file_name": file_name,
            "fileID": fileID,
            "data": None
        }
        
        header_size = sys.getsizeof(msg_packet) 
        
        try:
            with open(file_path, "r") as f:
                
                msg_packet["dataAmount"] = len(f.readlines())
                f.seek(0)
                msg_packet["data"] = f.read()

                """ 
                while buffer := f.read(MAX_SIZE - header_size):
                    msg_packet["data"] = buffer
                    self.clientSocket.send(pickle.dumps(msg_packet))
                 """
            self.clientSocket.send(pickle.dumps(msg_packet))
                
        except:
            print(f"UED Error: {file_name} does not exist")
            return

        try:
            reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
                
            # successful authentication
            if reply["status"] == 200:
                print(f"[UED] Uploaded {file_name}")
            
            else:
                raise Exception()
        except:
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
        
      
    
    def aed(self, command):
        
        # send aed request       
        self.clientSocket.send(pickle.dumps({"cmd": "AED", "devicename": self.devicename}))

        # process reply
        reply = pickle.loads(self.clientSocket.recv(MAX_SIZE))
        
        if reply["status"] == 200:
            for msg in reply["msg"]:
                print(f"[{msg['device']}] listening on {msg['addr']}:{msg['port']}. Active since {msg['timestamp']}.")
            
        elif reply["status"] == 400:
            print(f"[AED] Server: No other active edge devices.")
            
        elif reply["status"] == 404:
            print(f"[AED] Error: cannot determine active edge devices.")
        
        

    
    def out(self, command):
        print("Out command")
        
        self.clientSocket.send(pickle.dumps({"cmd": "OUT"}))
        self.clientSocket.close()
    
    def getHelp(self):
        print("""Available commands
    EDG - Edge data generation
    UED - Upload edge data
    SCS - Server computation Service
    DTE - Delete data file
    AED - Active Edge Devices
    OUT - Exit Edge network
    """)
 


def main():
    
    try:
        serverIp = sys.argv[1]
        serverPort = int(sys.argv[2])
        p2pUDPPort = int(sys.argv[3])
    except:
        print(f"Usage: {sys.argv[0]} <server-ip-address> <server-port-number: int> <P2P-UDP-server-port-number: int>")
        sys.exit(1)
    

    client = P2PClient(serverIp, serverPort, p2pUDPPort)
    client.authenticate()
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
            client.aed(command)
        elif command[0].upper() == "OUT":
            client.out(command)
            break
        elif command[0].upper() == "HELP":
            client.getHelp()
            
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