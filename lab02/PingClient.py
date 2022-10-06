#! /usr/bin/env python3


from socket import *
from datetime import datetime
from statistics import mean
import sys

def timedelta(start, end):
    return round((end - start).total_seconds() * 1000, 2)

def pingToServer(serverHost, serverPort, numTimes):

    # UDP connection
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    clientSocket.settimeout(0.6)
    

    rtt_store = []
    seq_num = 3330
    # send 15 ping messages
    for _ in range(numTimes):
        seq_num += 1
        message = f"PING {seq_num} {datetime.now()}\r\n" 

        start = datetime.now()
        clientSocket.sendto(message.encode(),(serverHost, serverPort))
        try:
            modifiedMessage, serverAddress = clientSocket.recvfrom(serverPort)
            end = datetime.now()
            rtt_store.append(timedelta(start, end))
            print(f"ping to {serverHost}, seq = {seq_num - 3330}, rtt = {timedelta(start, end)}ms")
        except:
            print(f"ping to {serverHost}, seq = {seq_num - 3330}, timed out")
            continue

    print("\nResponse RTT Stats:")
    print(f"Minimum RTT: {min(rtt_store)}ms")
    print(f"Maximum RTT: {max(rtt_store)}ms")
    print(f"Average RTT: {round(mean(rtt_store), 2)}ms")

    clientSocket.close()
    #and close the socket


if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print(f"Error: Usage: {sys.argv[0]} <Server-Host> <Server-Port>")
        sys.exit(1)
    
    serverHost = sys.argv[1]
    serverPort = int(sys.argv[2])
    pingToServer(serverHost, serverPort, 15)