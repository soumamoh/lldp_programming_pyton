#!/usr/bin/python3

import os
from struct import pack, unpack, calcsize
from __init__ import *
from sys import argv, exit


# ************************************************************************************ #
#                                                                                      #
#               Debut activité 4 : Implémentation de LLDP en Python                    #
#                                                                                      #
# ************************************************************************************ #

def get_macAddr(iface: str) -> bytes:
    """
    Retourne l'adresse MAC d'une interface réseau sous forme d'un tableau d'octets.
    
    Args:
        iface (str): Le nom de l'interface réseau (par exemple, "eth0").
    
    Returns:
        bytes: Tableau d'octets représentant l'adresse MAC.
               Retourne six octets nuls si l'interface n'est pas trouvée.
    """
    mac_path = f"/sys/class/net/{iface}/address"

    if not os.path.exists(mac_path):
        print(f"Path not found: {mac_path}")  # Message d'erreur indiquant que le chemin n'existe pas donc introuvable
        return b'\x00' * 6  # Retourne 6 octets nuls si l'interface n'existe pas
    else:
        # Lit le contenu du fichier avec la methode contexte manager ( with ... as mon_fichier: )
        with open(mac_path, 'r') as mac_file:
            mac_address = mac_file.read().strip()
        
        # Convertit l'adresse MAC en tableau d'octets
        # La fonction int(a,b) me permet de convertir l'entier a sur b bites
        # et la fonction bytes me cast l'ensemble de ces octets renvoyés en tableau d'octets
        return bytes(int(octet, 16) for octet in mac_address.split(':'))
    

def set_lldpHeader(iface: str, destMulticastGroup: str = 'bridge') -> bytes:
    """
    Génère l'entête Ethernet LLDP.
    
    Args:
        iface (str): Nom de l'interface réseau pour récupérer l'adresse MAC source.
        destMulticastGroup (str): Nom du groupe multicast de destination (par défaut 'Bridge').
    
    Returns:
        bytes: Tableau d'octets représentant l'entête Ethernet LLDP.
    
    Raises:
        ValueError: Si une valeur incorrecte est passée pour destMulticastGroup.
    """
    # Vérifie si le groupe multicast est valide
    if destMulticastGroup not in MULTICAST_ADDRESSES:
        raise ValueError(f"Invalid multicast group: {destMulticastGroup}")
    
    # Récupère l'adresse MAC de l'interface source
    src_mac = get_macAddr(iface)
    
    # Récupère l'adresse MAC de destination du groupe multicast
    dest_mac = MULTICAST_ADDRESSES[destMulticastGroup]
    
    # Ethernet Header : [Destination MAC] [Source MAC] [Type]
    eth_type = b'\x88\xcc'  # Type LLDP (0x88cc)
    
    # Crée l'entête Ethernet LLDP : 6 octets adr mac dst, 6 octets adr mac src et 2 octets l'ethertype
    lldp_header = dest_mac + src_mac + eth_type
    
    return lldp_header

    

# 4. Chassis ID TLV
def set_chassisTLV(iface: str = 'eth0', subtype: int = 4) -> bytes:
    """
    Crée le TLV « Chassis ID » pour LLDP.
    
    Cette fonction retourne un tableau d'octets représentant la TLV « Chassis ID », en utilisant :
    - Le type TLV = 0x01 (Chassis ID)
    - Le sous-type transmis (par défaut : 4 pour « MAC Address »)
    - L'adresse MAC de l'interface réseau spécifiée (par défaut : eth0)

    Args:
        iface (str): Nom de l'interface réseau (par défaut : eth0).
        subtype (int): Sous-type pour l'identifiant de châssis (par défaut : 4).

    Returns:
        bytes: Un tableau d'octets représentant la TLV « Chassis ID ».

    Raises:
        ValueError: Si l'adresse MAC récupérée est invalide ou si le sous-type est incorrect.
    """
    # Type TLV pour Chassis ID
    tlv_type = 0x01

    # Récupérer l'adresse MAC
    value = get_macAddr(iface)
    if len(value) != 6:  # Une adresse MAC valide fait 6 octets
        raise ValueError(f"L'adresse MAC récupérée pour {iface} est invalide : {value}")

    # Longueur totale : 1 octet pour le sous-type + 6 octets pour l'adresse MAC
    length = len(value) + 1

    # Construire le TLV
    # Forcer le systeme à adopter le format Big Indian, car c'est le format utilis en réseau pour l'envoie de packet
    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))  # Type et longueur MSB
    tlv_header_length = pack('!B', length & 0xFF)  # Longueur LSB
    tlv_information_string = pack('!B', subtype) + value  # Sous-type

    # Retourner le TLV complet
    return tlv_header_type + tlv_header_length + tlv_information_string


# 5. Port ID TLV
def set_portTLV(iface: str = 'eth1', subtype: int = 3):
    """Crée le TLV « Port ID » pour LLDP.

    Cette fonction génère un tableau d'octets représentant le TLV « Port ID », en utilisant :
    - Le type TLV associé à l'identifiant de port.
    - Le sous-type spécifié (par défaut : 3 pour « MAC Address »).
    - L'adresse MAC de l'interface LLDP active (par défaut : eth1).

    Args:
        iface (str): Nom de l'interface réseau à utiliser pour récupérer l'adresse MAC (par défaut : eth1).
        subtype (int): Sous-type pour l'identifiant de port (par défaut : 3 pour « MAC Address »).

    Returns:
        bytes: Un tableau d'octets représentant le TLV « Port ID ».

    Raises:
        ValueError: Si l'adresse MAC de l'interface spécifiée est invalide.
    """
    tlv_type = 0x02
    subtype = 0x03  # 3 > MAC address > MAC address (IEEE Std 802)
    value = get_macAddr(iface)
    if len(value) != 6:  # Une adresse MAC valide fait 6 octets
        raise ValueError(f"L'adresse MAC récupérée pour {iface} est invalide : {value}")
    length = len(value) + 1  # Subtype + Value

    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))
    tlv_header_length = pack('!B', length & 0xFF)
    tlv_information_string = pack('!B', subtype) + value

    # Retourner le TLV complet
    return tlv_header_type + tlv_header_length + tlv_information_string


def set_TTL(duration: int = 120):
    """
    Crée le TLV « Time To Live » pour LLDP.

    Cette fonction génère un tableau d'octets représentant le TLV « Time To Live » (TTL), 
    utilisé pour indiquer la durée de validité des informations LLDP.

    Args:
        seconds (int): Durée en secondes pour le champ TTL (par défaut : 120).

    Returns:
        bytes: Un tableau d'octets représentant le TLV « Time To Live » (TTL), 
            conforme à la spécification LLDP.

    Raises:
        ValueError: Si la valeur spécifiée pour `seconds` est en dehors des limites acceptées (0-65535).
    """

    tlv_type = 0x03
    length = 2  # TTL always 2 bytes

    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))
    tlv_header_length = pack('!B', length & 0xFF)
    tlv_information_string = pack('!H', duration)

    return tlv_header_type + tlv_header_length + tlv_information_string 


def set_endLLDPDU():
    """
    Crée la TLV de fin de LLDPDU.

    Cette fonction génère un tableau d'octets représentant la TLV de fin de LLDPDU, 
    qui marque la fin de la trame LLDP et permet de signaler que les informations 
    de cette unité de données ont été envoyées.

    Returns:
        bytes: Un tableau d'octets représentant la TLV de fin de LLDPDU, conforme 
            à la spécification LLDP.

    Raises:
        ValueError: Si un paramètre incorrect est fourni pour la génération de la TLV de fin.
        """


    tlv_type = 0x00
    length = 0

    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))
    tlv_information_string = pack('!B',length & 0xFF)
    
    return  tlv_header_type + tlv_information_string


def set_nameTLV() -> bytes:

    """
    Crée la TLV (Type-Length-Value) représentant le « System Name » (Nom du Système) dans un paquet d'octets.

    Cette fonction exécute la commande système 'hostname' pour obtenir le nom du système (nom d'hôte) de la machine. 
    Elle renvoie ensuite un paquet d'octets représentant la TLV « System Name » dans le format suivant :
    - Type : 0x0C (TLV type pour System Name)
    - Length : Longueur du nom du système
    - Value : Le nom du système (nom d'hôte) sous forme de chaîne d'octets encodée en UTF-8.

    Le paquet d'octets retourné peut être intégré dans une trame LLDP pour fournir des informations sur le nom du système.

    Returns:
        bytes: Paquet d'octets représentant la TLV « System Name ».
    
    Exemple:
        Si le nom du système est 'myhostname', la fonction retourne :
        b'\x0a\x0amyhostname'
    """

    # Execute bash command 'hostname' and store the result in file
    with os.popen("hostname") as fd :
        result = fd.readline().strip() # Read first line of filedescriptor and eliminate line breaks

     # Convertir chaque caractère en son équivalent byte (ASCII)
    hostname = result.encode('utf-8')
    
    tlv_type = 0x05
    length = len(hostname)

    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))
    tlv_header_length = pack('!B', length & 0xFF)
    tlv_information_string = hostname

    return tlv_header_type + tlv_header_length + tlv_information_string 


def set_descriptionTLV():
    """Crée le TLV (Type-Length-Value) « System Description » pour LLDP.

    Cette fonction récupère les informations système du serveur en exécutant 
    des commandes shell pour obtenir le nom du système (via `uname -srvmo`) 
    et le nom lisible de la distribution (via le fichier `/etc/os-release`).
    Elle concatène ces informations et les encode en UTF-8, puis construit 
    le TLV « System Description » sous la forme d'un paquet d'octets.

    Le paquet retourné contient le type TLV, la longueur de la description, 
    et la chaîne de caractères représentant la description du système.

    Retourne :
        bytes: Le paquet d'octets représentant le TLV « System Description ».
    """
    # Recuperer l'information systèmes avec la commande 'uname -srvmo'
    with os.popen("uname -srvmo") as fd :
        info_systeme = fd.readline().strip() # Read first line of filedescriptor and eliminate line breaks

    # Recuperer l'information le 'PRETTY_NAME' du système
    with os.popen("cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2") as fd :
        pretty_name = fd.readline().strip().strip('"') # Read first line of filedescriptor and eliminate line breaks

    sys_decription = (pretty_name + ' ' + info_systeme).encode('utf-8')

    tlv_type = 0x06
    length = len(sys_decription)

    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))
    tlv_header_length = pack('!B', length & 0xFF)
    tlv_information_string = sys_decription

    return tlv_header_type + tlv_header_length + tlv_information_string 


def set_portDescriptionTLV(port_description: str = "eth1") -> bytes:
    """
    Crée une TLV de description de port pour LLDP (Type 4).
    
    Arguments:
    port_description (str): La description du port, par défaut "Unknown Port".
    
    Retour:
    bytes: Un paquet d'octets représentant la TLV de description du port.
    """
    # Encoder la description du port en bytes
    port_description_bytes = port_description.encode('utf-8')
    
    tlv_type = 0x04
    length = len(port_description_bytes)
    
    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))
    tlv_header_length = pack('!B', length & 0xFF)
    tlv_information_string = port_description_bytes

    return tlv_header_type + tlv_header_length + tlv_information_string


def set_capabilitiesTLV(capabilities: tuple = default_capabilities) -> bytes:
    """
    Crée une TLV « System Capabilities » pour LLDP.
    
    Args:
        capabilities (tuple): Tuple de tuples représentant les couples « activity/enabled »
                              des fonctionnalités disponibles et activées.

    Returns:
        bytes: Un tableau d'octets représentant la TLV « System Capabilities ».
    """
    capabilities_available = 0
    capabilities_enabled = 0

    # Parcourt les couples (nom, état) dans le paramètre capabilities
    for name, enabled in capabilities:
        # Trouver la position du bit associée à la capacité et -1 si capacité pas trouvée
        bit_position = next((pos for cap, pos in SYSTEM_CAPABILITIES if cap == name), -1)
        
        if bit_position == -1:
            raise ValueError(f"Capacité système inconnue : {name}")
        
        # Positionner le bit dans "capabilities available"
        capabilities_available |= (1 << bit_position)

        # Positionner le bit dans "capabilities enabled" si activé
        if enabled:
            capabilities_enabled |= (1 << bit_position)

    # Construire la TLV
    tlv_type = 0x07  # Type pour "System Capabilities"
    length = 4  # Deux octets pour chaque champ

    tlv_header_type = pack('!B', (tlv_type << 1) | ((length >> 8) & 0x01))
    tlv_header_length = pack('!B', length & 0xFF)
    tlv_information_string = pack('!HH', capabilities_available, capabilities_enabled)

    return tlv_header_type + tlv_header_length + tlv_information_string

# ************************************************************************************ #
#                                                                                      #
#                Fin activité 4 : Implémentation de LLDP en Python                     #
#                                                                                      #
# ************************************************************************************ #




# ************************************************************************************ #
#                                                                                      #
#  Debut activité 5 : Récupération et traitement des trames d'annonces LLDP en Python  #
#                                                                                      #
# ************************************************************************************ #
        
def get_lldpHeader(frame: bytes) -> tuple :

    if len(frame) < ETHER_HEADER_LEN:
        raise ValueError("The frame is too short to contain an Ethernet header.")
    
    frame_header = frame[:ETHER_HEADER_LEN]
    motif = '!6s6sH'

    dst_mac, src_mac, eth_type = unpack(motif,frame_header)

    # Convertir les adresses MAC en chaîne lisible (uu:vv:ww:xx:yy:zz)
    dest_mac_str = ":".join(f"{byte:02x}" for byte in dst_mac)
    src_mac_str = ":".join(f"{byte:02x}" for byte in src_mac)

    # Convertir le type Ethernet en hexadécimal
    eth_type_str = f"0x{eth_type:04x}"

    # Retourner les données sous forme de tuple
    return dest_mac_str, src_mac_str, eth_type_str

def tlvHeader(header: bytes) -> tuple :

    if len(header) < HEADER_TLV_LEN:
        raise ValueError("/!\ Tlv header error : The length of the TLV header must be exactly 2 bytes.")
        
    motif = '!BB'
    
    # Récuperer le type de la tlv et sa longueur
    tlv_type, tlv_length = unpack(motif,header)

    # Extraire la longueur (1 octet), et appliquer le décalage
    tlv_length_high = (tlv_type & 0x01) << 8  # Partie haute du length
    tlv_length_low = tlv_length  # Partie basse du length
    tlv_length = tlv_length_high | tlv_length_low  # Longueur totale du TLV

    return tlv_type, tlv_length

def get_allTLVs(datas: bytes) -> list :
    # Initialiser un index pour parcourir les TLVs
    index = 0
    tlvs = []

    # Parser les TLVs jusqu'à la fin de la trame
    while index < len(datas):
        # Lire le type du TLV (1 octet) et longueur totale de la TLV
        tlv_type, tlv_length = tlvHeader(datas[index:index+2])

        # Extraire la valeur en fonction de la longueur
        tlv_value = datas[index + 2: index + 2 + tlv_length]  # -2 pour enlever type et length
        # Ajouter le TLV dans la liste (stocke le type, la longueur et la valeur)
        tlvs.append((tlv_type >> 1, tlv_length, tlv_value))  # On décale le type pour récupérer le vrai type

        # Mettre à jour l'index pour le prochain TLV
        index += 2 + tlv_length

    return tlvs

# Fonction intermediaire qui me permet de traiter le subtype d'un Chassis ID TLV
def process_chassis_tlv_subtype(subtype: int, value: bytes) -> str:
    """
    Traite une TLV en fonction de son sous-type.

    :param subtype: Le sous-type de la TLV.
    :param value: La valeur brute associée au sous-type (en bytes).
    :return: Une représentation formatée de la valeur.
    """
    if subtype == 4:  # Sous-type "MAC address"
        # Vérifier que la longueur de l'adresse MAC est correcte
        if len(value) != 6:
            raise ValueError("Invalid MAC address length for TLV subtype 4.")
        
        # Convertir les octets en format uu:vv:ww:xx:yy:zz
        return ":".join(f"{byte:02x}" for byte in value)

    elif subtype in (1, 2, 3, 6, 7):  # Chassis component, Interface alias, etc.
        # Traiter comme une chaîne UTF-8 décodée si pertinent
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError(f"Invalid UTF-8 encoding for TLV subtype {subtype}.")

    elif subtype == 5:  # Network address
        # Identifier le type d'adresse réseau (par exemple IPv4 ou IPv6)
        if len(value) == 4:  # IPv4
            return ".".join(str(byte) for byte in value)
        elif len(value) == 16:  # IPv6
            return ":".join(f"{value[i]:02x}{value[i+1]:02x}" for i in range(0, 16, 2))
        else:
            raise ValueError("Invalid network address length for TLV subtype 5.")

    else:
        raise ValueError(f"Unsupported TLV subtype {subtype}.")



def get_chassisTLV(tlv: tuple) -> tuple :
    """
    Extrait et formate les informations d'une TLV de type "Chassis ID".
    
    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Sous-type du Chassis ID (entier).
        - tlv[1] : longueur de la donnée  du tlv Chassis ID (entier).
        - tlv[2] : Donnée brute associée au Chassis ID (en bytes).
    
    :return: Un tuple composé de :
        - Une chaîne de caractères décrivant le sous-type de Chassis ID 
          (issue de la donnée d'initialisation « CHASSIS_ID »).
        - Une représentation formatée de l'information associée, selon le sous-type :
            - Pour le sous-type "MAC address" (4), la valeur est formatée comme uu:vv:ww:xx:yy:zz.
            - Pour les autres sous-types, la valeur est retournée sous une forme lisible ou spécifique au type.
    
    :raises ValueError: Si le sous-type n'est pas supporté ou si la donnée brute est invalide.
    """
    # Vérifie si le type de la tlv recuperé match avec la tlv chassis
    if tlv[0] != 1:
        raise ValueError(f"The parameter type does not match the expected TLV type. : Chassis ID tlv type = 0x01")
    
    # Verification du subtype de la tlv chassis
    subtype = tlv[2][0]
    return CHASSIS_ID[subtype - 1][1], process_chassis_tlv_subtype(subtype,tlv[2][1:])

# Fonction intermediaire qui me permet de traiter le subtype d'un Port ID TLV
def process_port_tlv_subtype(subtype: int, value: bytes) -> str:
    """
    Traite une TLV de type "Port ID" en fonction de son sous-type.

    :param subtype: Le sous-type du Port ID (entier).
    :param value: La valeur brute associée au Port ID (en bytes).
    :return: Une représentation formatée de la valeur, selon le sous-type :
        - Pour le sous-type "MAC address" (3), la valeur est formatée comme uu:vv:ww:xx:yy:zz.
        - Pour les sous-types "Network address" (4), elle est interprétée comme une adresse réseau.
        - Pour les autres sous-types, la valeur est interprétée comme une chaîne UTF-8.
    
    :raises ValueError: Si le sous-type n'est pas supporté ou si la donnée brute est invalide.
    """
    if subtype == 3:  # Sous-type "MAC address"
        # Vérifier que la longueur de l'adresse MAC est correcte
        if len(value) != 6:
            raise ValueError("Invalid MAC address length for Port ID subtype 3.")
        
        # Convertir les octets en format uu:vv:ww:xx:yy:zz
        return ":".join(f"{byte:02x}" for byte in value)

    elif subtype == 4:  # Sous-type "Network address"
        # Identifier le type d'adresse réseau (par exemple IPv4 ou IPv6)
        if len(value) == 4:  # IPv4
            return ".".join(str(byte) for byte in value)
        elif len(value) == 16:  # IPv6
            return ":".join(f"{value[i]:02x}{value[i+1]:02x}" for i in range(0, 16, 2))
        else:
            raise ValueError("Invalid network address length for Port ID subtype 4.")

    elif subtype in (1, 2, 5, 6, 7):  # Interface alias, Port component, etc.
        # Traiter comme une chaîne UTF-8 décodée si possible
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError(f"Invalid UTF-8 encoding for Port ID subtype {subtype}.")

    else:
        raise ValueError(f"Unsupported Port ID subtype {subtype}.")

def get_portTLV(tlv: tuple) -> tuple:
    """
    Extrait et formate les informations d'une TLV de type "Port ID".
    
    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Sous-type du Port ID (entier).
        - tlv[1] : longueur de la donnée  du tlv Port ID (entier).
        - tlv[2] : Donnée brute associée au Port ID (en bytes).
    
    :return: Un tuple composé de :
        - Une chaîne de caractères décrivant le sous-type de Port ID 
          (issue de la donnée d'initialisation « PORT_ID »).
        - Une représentation formatée de l'information associée, selon le sous-type :
            - Pour le sous-type "MAC address" (3), la valeur est formatée comme uu:vv:ww:xx:yy:zz.
            - Pour les autres sous-types, la valeur est retournée sous une forme lisible ou spécifique au type.
    
    :raises ValueError: Si le sous-type n'est pas supporté ou si la donnée brute est invalide.
    """
    # Vérifie si le type de la tlv recuperé match avec la tlv chassis
    if tlv[0] != 2:
        raise ValueError(f"The parameter type does not match the expected TLV type. : Port ID tlv type = 0x01")
    
    # Verification du subtype de la tlv port
    subtype = tlv[2][0]
    return PORT_ID[subtype - 1][1], process_port_tlv_subtype(subtype,tlv[2][1:])
    
def get_TTL(tlv: tuple) -> int :
    """
    Extrait et retourne la valeur "Time To Live" (TTL) d'une TLV.

    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Le type de la TLV (doit correspondre au type TTL attendu).
        - tlv[1] : longueur de la donnée  du tlv TTL (entier).
        - tlv[2] : La donnée brute de la TLV (en bytes), représentant le TTL.
    
    :return: Un entier représentant la durée "Time To Live" en secondes.

    :raises ValueError: Si la TLV est invalide, par exemple :
        - Si le type de TLV ne correspond pas à "Time To Live".
        - Si la donnée brute n'a pas la longueur attendue pour un TTL.
    """
    # Vérifie si le type de la tlv recuperé match avec la tlv chassis
    if tlv[0] != 3:
        raise ValueError(f"The parameter type does not match the expected TLV type. : TTL tlv type = 0x03")
    
    return int.from_bytes(tlv[2], byteorder='big')

def get_endLLDPDU(tlv: tuple) -> str :
    """
    Vérifie et traite une TLV marquant la fin d'une PDU LLDP.

    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Le type de la TLV (doit correspondre au type "End of LLDPDU").
        - tlv[1] : longueur de la donnée du tlv End of LLDPDU (entier), la donnée brute associée à la TLV, attendue est vide pour ce type.
    
    :return: Une chaîne vide (`""`) pour indiquer que la TLV de fin est correctement traitée.

    :raises ValueError: Si la TLV est invalide, par exemple :
        - Si le type de TLV ne correspond pas au type "End of LLDPDU".
        - Si la donnée brute n'est pas vide, ce qui n'est pas attendu pour une TLV de fin.
    """
    # Vérifie si le type de la tlv recuperé match avec la tlv chassis
    if tlv[0] != 0:
        raise ValueError(f"The parameter type does not match the expected TLV type. : End Of LLDPDU TLV = 0x00")
    
    return ""

def get_sysNameTLV(tlv: tuple) -> str :
    """
    Extrait et retourne la chaîne d'information d'une TLV de type "System Name".

    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Le type de la TLV (doit correspondre au type "System Name").
        - tlv[1] : longueur de la donnée du tlv (optionnel) System Name (entier).
        - tlv[2] : La donnée brute associée à la TLV (en bytes), représentant le nom du système.

    :return: Une chaîne de caractères représentant le nom du système (décodée en UTF-8).

    :raises ValueError: Si la TLV est invalide, par exemple :
        - Si le type de TLV ne correspond pas à "System Name".
        - Si la donnée brute ne peut pas être décodée en UTF-8.
    """
    # Vérifie si le type de la tlv recuperé match avec la tlv chassis
    if tlv[0] != 5:
        raise ValueError(f"The parameter type does not match the expected TLV type. : System Name TLV Type = 0x05")
    
    return tlv[2].decode('utf-8')



def get_sysDescrTLV(tlv: tuple) -> str :
    """
    Extrait et retourne la chaîne d'information d'une TLV de type "System Description".

    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Le type de la TLV (doit correspondre au type "System Description").
        - tlv[1] : longueur de la donnée du tlv (optionnel) System Description (entier).
        - tlv[2] : La donnée brute associée à la TLV (en bytes), représentant la description du système.

    :return: Une chaîne de caractères représentant la description du système (décodée en UTF-8).

    :raises ValueError: Si la TLV est invalide, par exemple :
        - Si le type de TLV ne correspond pas à "System Description".
        - Si la donnée brute ne peut pas être décodée en UTF-8.
    """
    # Vérifie si le type de la tlv recuperé match avec la tlv chassis
    if tlv[0] != 6:
        raise ValueError(f"The parameter type does not match the expected TLV type. : System Description TLV Type = 0x06")
    
    return tlv[2].decode('utf-8')

def get_portDescrTLV(tlv: tuple) -> str :
    """
    Extrait et retourne la chaîne d'information d'une TLV de type "Port Description".

    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Le type de la TLV (doit correspondre au type "Port Description").
        - tlv[1] : longueur de la donnée du tlv (optionnel) Port Description (entier).
        - tlv[2] : La donnée brute associée à la TLV (en bytes), représentant la description du port.

    :return: Une chaîne de caractères représentant la description du port (décodée en UTF-8).

    :raises ValueError: Si la TLV est invalide, par exemple :
        - Si le type de TLV ne correspond pas à "Port Description".
        - Si la donnée brute ne peut pas être décodée en UTF-8.
    """
    # Vérifie si le type de la tlv recuperé match avec la tlv chassis
    if tlv[0] != 4:
        raise ValueError(f"The parameter type does not match the expected TLV type. : Port Description TLV Type = 0x04")
    
    return tlv[2].decode('utf-8')

def get_capabilitiesTLV(tlv: tuple) -> tuple :
    """
    Extrait les fonctionnalités disponibles et activées à partir d'une TLV de type "System Capabilities".
    
    :param tlv: Un tuple contenant les informations de la TLV, où :
        - tlv[0] : Le type de la TLV (doit correspondre au type "System Capabilities").
        - tlv[1] : La longueur de la TLV (pas utilisé dans ce cas, mais généralement présent).
        - tlv[2] : La valeur brute de la TLV contenant les fonctionnalités sous forme binaire.
        
    :return: Un tuple de deux entiers :
        - Le premier entier représente les fonctionnalités disponibles (relativement aux zéros et aux uns binaires).
        - Le second entier représente les fonctionnalités activées (relativement aux zéros et aux uns binaires).
    
    :raises ValueError: Si la TLV est invalide, par exemple :
        - Si le type de la TLV ne correspond pas à "System Capabilities".
        - Si la donnée brute ne contient pas suffisamment d'octets pour représenter les fonctionnalités disponibles et activées.
    """
    
    # Vérification du type de la TLV
    if tlv[0] != 7: 
        raise ValueError(f"The parameter type does not match the expected TLV type. : System Capabilities TLV Type = 0x07")
    
    # Extraction de la valeur brute
    capabilities_data = tlv[2]
    
    # Conversion des deux octets en entiers
    available = capabilities_data[0:2]  # 2 premiers octets représentent les fonctionnalités disponibles
    activated = capabilities_data[2:]  # 2 deuxièmes octets représentent les fonctionnalités activées
    
    return (int.from_bytes(available, byteorder='big'), int.from_bytes(activated, byteorder='big'))

# Fonction intermediaire qui me permet de renvoyer les tuples dans un dictionnaire qui match avec sa tlv
def get_tlv_by_type(datas: list) -> dict:
    """
    Recherche et retourne le tuple correspondant au type de TLV donné.
    
    :param datas: Liste des tuples TLV.
    :return: Le dictionnaire de tuple correspondant au type de TLV.
    """
    tlvs_dict = {}

    for t in datas:
        tlvs_dict[t[0]] = t   
    
    return tlvs_dict

# Fonction intermediaire qui me permet de traiter les capabilities
def process_capabilities(system_capabilities: bytes, enable_capabilities: bytes) -> dict:
    
    capabilities = {}
    
    for bit_position, name in enumerate(SYSTEM_CAP):
        mask = 0x0001 << bit_position
        sys_cap = system_capabilities & mask
        ena_cap = enable_capabilities & mask
        if sys_cap:  # La capacité système est présente
            capabilities[name] = "on" if ena_cap else "off"
    
    return capabilities

def show_lldp_neighbors(datas: bytes) -> None :
    """
    Extrait et affiche les informations des voisins LLDP à partir des données de l'annonce LLDP.

    La fonction utilise la fonction 'get_allTLVs' pour extraire toutes les TLVs présentes dans l'annonce LLDP.
    Ensuite, elle traite chaque TLV à l'aide des fonctions de traitement spécifiques (telles que 'get_chassisTLV', 'get_portTLV', etc.)
    et affiche les propriétés des voisins, similaires à la sortie de la commande 'LLDPCLI show neighbors'.

    Résultat attendu :
    - Chassis :
        - ChassisID:    mac aa:bb:cc:00:01:00
        - SysName:      R1.chalons.univ-reims.fr
        - SysDescr:     Cisco IOS Software, Linux Software (I86BI_LINUX-ADVENTERPRISEK9-M), Version 15.5(2)T, DEVELOPMENT TEST SOFTWARE
                        Technical Support: http://www.cisco.com/techsupport
                        Copyright (c) 1986-2015 by Cisco Systems, Inc.
                        Compiled Thu 26-Mar-15 07:36 by prod_rel_tea
        - Capability:   Bridge, off
        - Capability:   Router, on
    - Port :
        - PortID:       ifname Et0/0
        - PortDescr:    Ethernet0/0
        - TTL:          10

    :param datas: Les données brutes de l'annonce LLDP (en bytes) à analyser.
    :return: None
    """

    tlvs = get_allTLVs(datas[14:])
    tlvs_dict = get_tlv_by_type(tlvs)
    print(f"Chassis:\n")
    print( f"\tChassisID:\tmac {get_chassisTLV(tlvs_dict[TLVS['Chassis ID']])[1]}")
    print(f"\tSysName:\t{get_sysNameTLV(tlvs_dict[TLVS['System Name']])}")
    print(f"\tSysDescr:\t{get_sysDescrTLV(tlvs_dict[TLVS['System Description']])}")
    available, activated = get_capabilitiesTLV(tlvs_dict[TLVS['System Capabilities']])
    capabilities = process_capabilities(available, activated)
    for capability, status in capabilities.items():
        print(f"\tCapability:\t{capability}, {status}")
    print(f"Port:\n")
    print(f"\tPortID:    \tifname {get_portTLV(tlvs_dict[TLVS['Port ID']])[1]}")
    print(f"\tPortDescr:\t{get_portDescrTLV(tlvs_dict[TLVS['Port Description']])}")
    print(f"\tTTL:      \t{get_TTL(tlvs_dict[TLVS['Time to Live']])}")
    


# Exemple d'utilisation
if __name__ == "__main__":

    # Vérifie si un argument a été passé
    # if len(argv) < 2:
    #     print("Usage: python3 lldp.py <iface_name> (eth0/lo/docker0)")
    #     exit(1)
    # interface = input("iface net : ") # Indiquer l'interface réseau sur laquelle on souhaite envoyer la trame
    # Récupère le premier argument (en dehors du nom du script)

    # iface_name = argv[1] # l'interface réseau sur laquelle on souhaite envoyer la trame
    # lldp_header = set_lldpHeader(iface_name,"LLDP")
    # chassisTLV = set_chassisTLV()
    # tlv_end = set_endLLDPDU()
    # print(f"{tlv_end}")
    print(get_lldpHeader(b'\x01\x80\xc2\x00\x00\x0e\x00\x15\x5d\xad\xa9\xd7\x88\xcc'))