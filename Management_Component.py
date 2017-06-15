#!/usr/bin/python

# Author: Christina Meyer
# Last update: 14.06.2017
# Description: The following Python script represents the Management Component of the distributed Intrusion Detection
#              System. It acts as a server and provides TCP sockets in order to receive intrusion alert messages from
#              several sensors (clients) across domain borders.

import socket
import sys


class Server():

    # Define instantiation of the Server class (like a constructor)
    # Specify the server address and the maximum number of clients that can connect to this server
    def __init__(self, Adress=('192.168.2.42', 6667), MaxClient=1):
        # Create TCP socket and bind it to the given address
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(Adress)
        # Listening to clients (restricted by the previously defined maximum)
        self.s.listen(MaxClient)
        print("Listening for the client..")

    # Wait for a connection ...
    def waitForConnection(self):
        while True:
            # Wait for an incoming connection and return a new socket, that represents the corresponding connection,
            # and the client address
            self.Client, self.Adr = (self.s.accept())
            print('Got a connection from: ' + str(self.Client) + '.')
            # Receive data from the client (limited by a maximum of 4096 bytes)
            received = self.Client.recv(4096)
            print("Received: {}".format(received))
            # Handling the case when a client got disconnected
            if received.strip() == "disconnect":
                self.s.close()
                sys.exit ("Received message. Shutting down.")
            elif received:
                print("Message received from client:")
                print(received)

    def main(self):
        s = Server()
        s.waitForConnection()

    if __name__ == '__main__':
        main()


