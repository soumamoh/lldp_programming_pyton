#!/usr/bin/python3

import sys
sys.path.append('/home/user/s105-mohamed-kevin-soumahoro/activite_5/appli_lldp')
import socket
from struct import pack, unpack, calcsize
from sys import argv, exit
from datetime import datetime, timedelta
from __init__ import *
from lldp import *


def receive_lldp_frame(interface='eth1'):
    """
    Fonction qui écoute sur une interface donnée et retourne une trame LLDP reçue.
    """
    # DEBUT TACHE 2
    # start = datetime.now()
    # duration = timedelta(seconds=60)
    # while datetime.now() - start < duration:
    #     # Create a raw socket using AF_PACKET
    #     sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    #     sock.bind(('eth0', 0))  # Replace with your interface name
    #     print(f"Awaiting incoming LLDP frame on network interface {interface}...")
    #     # Receive packets, the size of the buffer receiving the datas is 65535 bytes
    #     raw_data, addr = sock.recvfrom(65535)
    #     print(addr, raw_data)
    # FIN TACHE 2

    # DEBUT TACHE 3
    start = datetime.now()
    duration = timedelta(seconds=60)
    while datetime.now() - start < duration:
        # Create a raw socket using AF_PACKET
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((interface, 0))  # Replace with your interface name
        print(f"Awaiting incoming LLDP frame on network interface {interface}...")

        # Receive packets, the size of the buffer receiving the datas is 65535 bytes
        raw_data, addr = sock.recvfrom(65535)

        # Convertir l'ethertype en tableau de bytes
        ethertype_d = addr[1]
        ethertype = ethertype_d.to_bytes(2, byteorder='big')  # Utilisation de 2 bytes en big-endian
        
        if ethertype == ETHER_TYPE:
            # tlvs = get_allTLVs(raw_data[14:])
            # print(tlvs)
            # print(get_chassisTLV(tlvs[0]))
            # print(get_portTLV(tlvs[1]))
            # print(get_TTL(tlvs[2]))
            # print(get_capabilitiesTLV(tlvs[-2]))
            show_lldp_neighbors(raw_data)
            break

        sock.close()
    # return addr, raw_data


if __name__=="__main__":
    receive_lldp_frame()