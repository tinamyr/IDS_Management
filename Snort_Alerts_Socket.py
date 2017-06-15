#! /usr/bin/env python

# Author: Christina Meyer
# Last update: 14.06.2017
# Description: The following Python script represents the connection to the Network based Intrusion Detection System
#              'Snort'. On one site it acts as a Server and provides a UNIX socket to Snort, in order to retrieve the
#              intrusion alerts from Snort. On the other site this script acts as a client, that connects and sends the
#              alerts via TCP socket to the Management Component.

import os
import sys
import socket
import struct
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
import json

# Define variables for the length of an alert message etc.
ALERTMSG_LENGTH = 256
SNAPLEN = 1500

# Address of the Management Component
ADDRESS = ('192.168.2.42', 6667)

# The on_alert method takes the message, source and destination address of an alert as parameter, creates a TCP socket,
# that connects to the Management Component and transmits these data to the Management Component.
def on_alert(msg, src, dst):
    print ("Message: " + msg + " Source: " + src + " Destination: " + dst)
    recv_data = {'Message': msg, 'Source': src, 'Destination': dst}
    # Convert the data to json format
    json_data = json.dumps(recv_data)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(ADDRESS)
    try:
        # The TCP socket s sends the alerts data to the Management Component, using the correct encoding
        s.sendall(json_data.encode('utf-8'))
        print("Send to server...")
    except socket.error:
            print('Send failed')
            sys.exit()

# The main() method
def main():
    # Define the path where to provide the socket for snort and delete the socket, if it already exists.
    in_socket = os.path.join('/var/log/snort', 'snort_alert')
    if os.path.exists(in_socket):
        os.remove(in_socket)
        # Set the permissions (limited by this process) in order to access the socket path
        os.umask(0o755)

    print("Opening socket...")
    # Create the UNIX socket, which serves as Snort alert output
    # Snort supports only UDP sockets (SOCK_DGRAM)
    snortsocket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # Define the format string
    fmt = "%ds9I%ds" % (ALERTMSG_LENGTH, SNAPLEN)
    # Calculate the size of the format string
    fmt_size = struct.calcsize(fmt)
    # Bind the created Snort Unix socket to the "in_socket" path
    snortsocket.bind(in_socket)

    while True:
        try:
            print("Listening...")
            # Receive data from Snort alerts as a two-tuple consisting of the transmitted data and address information
            (datain, addr) = snortsocket.recvfrom(4096)
            # Apply the previously defined format to the alert messages
            (msg, ts_sec, ts_usec, caplen, pktlen, dlthdr, nethdr, transhdr, data, val, pkt) = \
                struct.unpack(fmt, datain[:fmt_size])
            msg = msg.decode('utf-8').strip('\x00')
            ether = Ether(pkt)
            # Call the on_alert method with the message, source and destination address from the received alerts
            # as parameters
            on_alert(msg, ether[IP].src, ether[IP].dst)
        except struct.error as e:
            print("Bad message?(msglen=%d): %s" % (len(datain), e.message))

    print("Done")

if __name__ == '__main__':
    main()