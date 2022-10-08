#! /usr/bin/env python3 

from socket import *
import pickle
import pickle
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

            msg = pickle.dumps({"cmd": "auth", "devicename": self.devicename, "password": password})
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
        
        
        

    def edg(self, command):
        print("EDG command") 
    
    def ued(self, command):
        print("UED command")
    
    def scs(self, command):
        print("SCS command")
    
    def dte(self, command):
        print("DTE command")
    
    def aed(self, command):
        print("AED command")
    
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
        
        if command[0] == "EDG":
            client.edg(command)
        elif command[0] == "UED":
            client.ued(command)
        elif command[0] == "SCS":
            client.scs(command)
        elif command[0] == "DTE":
            client.dte(command)
        elif command[0] == "AED":
            client.aed(command)
        elif command[0] == "OUT":
            client.out(command)
            break
        elif command[0] == "HELP":
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

Resulting filename:
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