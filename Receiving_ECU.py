import json
import can4python as can
import socket
import sys


# Set counter that will be used for counting CAN signals
received_signals = 0

# Adress to connect to the Management Component
address = ('192.168.2.42', 6667)

file = open("signal_description.txt","w")

# Create a CAN Bus, the communication relationships in the CAN network are defined in the *.kcd file
# ego_node_ids defines a node or a list of nodes that will be enacted
bus = can.CanBus.from_kcd_file('doc_example.kcd', 'vcan0', ego_node_ids=["2"])

# With the help of the previously defined counter, check if the received CAN signals on this node exceed the
# predefined number of 4 signals. If this is the case, print out a warning and send the corresponding signal values
# to the Management Component
while (received_signals <=4):
    received_signals = received_signals + 1
    received_signal_values = bus.recv_next_signals()
    print(received_signal_values)

print("Potential DOS Attack detected!!!")
signal_description = bus.get_descriptive_ascii_art()
description_file = file.write(signal_description)
signal_string = json.dumps(received_signal_values)
description_string = json.dumps(description_file)
received_signals = 0


# Create TCP Socket, connect to the Management Component and send the received CAN signals that possibly caused an
# DOS attack to the Management Component
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(address)
try:
  s.sendall(signal_string.encode('utf-8'))
  s.sendall(signal_description.encode('utf-8'))
except socket.error:
    print("Send failed")
    sys.exit()
