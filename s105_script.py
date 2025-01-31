#!/usr/bin/python3

import sys
sys.path.append('/home/user/s105-mohamed-kevin-soumahoro/activite_5/appli_lldp')
import socket
from sys import argv, exit
from lldp import *



def send_lldp_frame(iface : str = 'eth1'):

    """
    Envoie une trame LLDP sur le réseau via un socket RAW.

    Cette fonction crée un socket de type RAW (niveau Ethernet) et l'associe à
    l'interface réseau spécifiée (par défaut 'eth0'). Elle assemble ensuite
    la trame LLDP en combinant les différentes TLV (Type-Length-Value) nécessaires,
    telles que l'en-tête LLDP, les informations de châssis, de port, de nom, de description, 
    et les capacités, puis l'envoie sur le réseau.

    Paramètres :
        iface (str) : Le nom de l'interface réseau sur laquelle envoyer la trame (par défaut 'eth0').

    Retourne :
        None : La fonction n'a pas de valeur de retour. Elle envoie simplement la trame sur le réseau.
    
    Exemple d'utilisation :
        send_lldp_frame('eth0')
    """
    # Créer un socket RAW pour envoyer des trames Ethernet
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    
    # Associer le socket à l'interface réseau spécifiée (par défaut 'eth0')
    sock.bind((iface, 0))  # Remplacer 'eth0' par l'interface réseau correcte
    
    # Assemblage de la trame LLDP
    lldp_frame = set_lldpHeader(iface) + set_chassisTLV() + set_portTLV() + set_TTL() + set_nameTLV() + set_descriptionTLV() + set_portDescriptionTLV() + set_capabilitiesTLV() + set_endLLDPDU()

    # Envoyer la trame sur le réseau
    sock.send(lldp_frame)
    
    print("Trame LLDP envoyée avec succès sur l'interface", iface)


if __name__=="__main__":
    # Vérifie si un argument a été passé
    # if len(argv) < 2:
    #     print("Usage: python3 recevoir_trame_lldp.py <interface>")
    #     exit(1)
    # # interface = input("iface net : ") # Indiquer l'interface réseau sur laquelle on souhaite envoyer la trame
    # # Récupère le premier argument (en dehors du nom du script)
    # interface = argv[1] # Indique l'interface réseau sur laquelle on souhaite envoyer la trame
    send_lldp_frame()