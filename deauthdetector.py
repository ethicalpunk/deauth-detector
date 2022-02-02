error = False # Do not touch this variable
seq = 1 # Do not touch this variable
from datetime import datetime
from scapy.all import *
from netaddr import EUI, NotRegisteredError
import sys
from threading import Thread
import os

save = False # Put this to True if you want to save all output to the file ./database/savebase.txt


if save == True or save == False: # This block checks if the variable (save = ) was formatted correctly
    pass
else:
    pythonfile = open(f"{sys.argv[0]}", "r").readlines()
    for x,a in enumerate(pythonfile):
        if a.startswith("save ="):
            print(f"The save variable: (save = {save}) on line:[{x}] is not formatted corectly? Try again in the following format.\n\nsave = False\nsave = True")
            sys.exit(0)

def getdate(): # This def block returns the at that time requested datetime object in this format: 2022/01/01 00:00:00
    datenow = datetime.now()
    date = datenow.strftime("%d/%m/%Y %H:%M:%S")
    return date

def PacketHandler(packet):
    if packet.haslayer(Dot11Deauth):
        ID = packet.addr2, packet.addr1 # First element in tuple = source, second element in tuple = destination

        try: # This block defines the Organizational Unique Identifier for the source MAC address
            source_oui = "_".join(EUI(ID[0]).oui.registration().org.split())

        except NotRegisteredError:
            source_oui = "UNK_OUI"

        try: # This block defines the Organizational Unique Identifier for the destination MAC address
            destination_oui = "_".join(EUI(ID[1]).oui.registration().org.split())

        except NotRegisteredError:
            destination_oui = "UNK_OUI"

        global seq
        data = f"{getdate()} | [DeAUTH-Packet({seq})] from source MAC: ({ID[0]} [{source_oui}]) to target MAC: ({ID[1]} [{destination_oui}])"; seq += 1

        if save == True:
            database = open("./database/savebase.txt", "a+"); database.write(f"{data}\n"); database.close()

        return data

def main():
    while True:
        try:
            sniff(iface=sys.argv[1], prn = PacketHandler, store=False)

        except OSError:
            print("Interface: {} is invalid!".format(sys.argv[1]))
            sys.argv[1] = input("Input interface: ")
        except IndexError:
            print("Usage: {} <interface>".format(sys.argv[0]))
            global error
            error = True
            break

Thread(target = main).start()

while True:
    try:
        if error == True:
            break

    except KeyboardInterrupt:
        sys.exit()

    time.sleep(0.1)
