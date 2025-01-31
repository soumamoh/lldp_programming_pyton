#!/usr/bin/python3

# Définition de constantes

ETHER_HEADER_LEN = 14

HEADER_TLV_LEN = 2

# Tableau d'octets difinissant l'Ethertype lldp.
ETHER_TYPE = b'\x88\xcc'

# Dictionnaire des adresses MAC multicast.
MULTICAST_ADDRESSES = {
    "bridge": b"\x01\x80\xc2\x00\x00\x0e",  # Propagation constrained to a single physical link; stopped by all types of bridge
    "notpmr": b"\x01\x80\xc2\x00\x00\x03",  # Propagation constrained by all bridges other than TPMRs; intended for use within provider bridged networks 
    "customer": b"\x01\x80\xc2\x00\x00\x00",  # Propagation constrained by customer bridges; this gives the same coverage as a customer-customer MACSec connection
}
 
TLV_TYPE = {
    0: b"End of LLDPDU",               # TLV indiquant la fin d'une unité de données LLDP
    1: b"Chassis ID",                  # Identifiant unique pour le châssis de l'équipement
    2: b"Port ID",                     # Identifiant unique pour le port
    3: b"Time to Live (TTL)",          # Durée de vie du message LLDP
    4: b"Port Description",            # Description textuelle du port
    5: b"System Name",                 # Nom du système
    6: b"System Description",          # Description du système
    7: b"System Capabilities",         # Capacités du système
    8: b"Management Address",          # Adresse de gestion du système
    127: b"Organizationally Specific"  # TLV défini par des organisations spécifiques
}

# Tuples ordonnés des identifiants de base
# Sous-types pour Chassis ID
CHASSIS_ID = (
    (1, b"Chassis component"),
    (2, b"Interface alias"),
    (3, b"Port component"),
    (4, b"MAC address"),
    (5, b"Network address"),
    (6, b"Interface name"),
    (7, b"Locally assigned")
)  

# Sous-types pour Port ID
PORT_ID = (
    (1, b"Interface alias"),
    (2, b"Port component"),
    (3, b"MAC address"),
    (4, b"Network address"),
    (5, b"Interface name"),
    (6, b"Agent circuit"),
    (7, b"Locally assigned")
)

# Tuple ordonné des capacités système
SYSTEM_CAPABILITIES = (("Other",0),("Repeater", 1),("MAC Bridge", 2),("WLAN Access Point", 3),("Router", 4),("Telephone", 5),("DOCSIS Cable Device", 6),("Station Only", 7),("C-VLAN Component", 8),("S-VLAN Component", 9),("Two-port MAC Relay", 10),("Two-port MAC Relay (TPMR)",11),("Reserved",12),("Reserved",13),("Reserved",14),("Reserved",15))      

# Dictionnaire Address Family Numbers
ADDR_FAMILY = {
    "Reserved": 0,
    "IP (IP version 4)": 1,
    "IP6 (IP version 6)": 2,
    "NSAP": 3,
    "HDLC (8-bit multidrop)": 4,
    "BBN 1822": 5,
    "802 (includes all 802 media plus Ethernet 'canonical format')": 6,
    "E.163": 7,
    "E.164 (SMDS, Frame Relay, ATM)": 8,
    "F.69 (Telex)": 9,
    "X.121 (X.25, Frame Relay)": 10,
    "IPX": 11,
    "Appletalk": 12,
    "Decnet IV": 13,
    "Banyan Vines": 14,
    "E.164 with NSAP format subaddress": 15,
    "DNS (Domain Name System)": 16,
    "Distinguished Name": 17,
    "AS Number": 18,
    "XTP over IP version 4": 19,
    "XTP over IP version 6": 20,
    "XTP native mode XTP": 21,
    "Fibre Channel World-Wide Port Name": 22,
    "Fibre Channel World-Wide Node Name": 23,
    "GWID": 24,
    "AFI for L2VPN information": 25,
    "MPLS-TP Section Endpoint Identifier": 26,
    "MPLS-TP LSP Endpoint Identifier": 27,
    "MPLS-TP Pseudowire Endpoint Identifier": 28,
    "MT IP: Multi-Topology IP version 4": 29,
    "MT IPv6: Multi-Topology IP version 6": 30,
    "BGP SFC": 31,
    "EIGRP Common Service Family": 16384,
    "EIGRP IPv4 Service Family": 16385,
    "EIGRP IPv6 Service Family": 16386,
    "LISP Canonical Address Format (LCAF)": 16387,
    "BGP-LS": 16388,
    "48-bit MAC": 16389,
    "64-bit MAC": 16390,
    "OUI": 16391,
    "MAC/24": 16392,
    "MAC/40": 16393,
    "IPv6/64": 16394,
    "RBridge Port ID": 16395,
    "TRILL Nickname": 16396,
    "Universally Unique Identifier (UUID)": 16397,
    "Routing Policy AFI": 16398,
    "MPLS Namespaces": 16399,
    "Unassigned": list(range(32, 16383 + 1)) + list(range(16400, 65534 + 1)),
    "Reserved (65535)": 65535
}


# Dictionnaire des modes de numérotation des interfaces
NB_METHOD = {
    "Unknown": 1,
    "ifIndex": 2,
    "system port number": 3
}

# TLVs spécifiques IEEE 802.1
ORGSPEC_802_1 = ((1, "Port VLAN ID"),(2, "Port And Protocol VLAN ID"),(3, "VLAN Name"),(4, "Protocol Identity"),(5, "VID Usage Digest"),   (6, "Management VID"),(7, "Link Aggregation"),(8, "Reserved"))

# TLVs spécifiques IEEE 802.3
ORGSPEC_802_3 = (
    (1, b"MAC/PHY Configuration/Status 79.3.1"),    
    (2, b"Power Via Medium Dependent Interface (MDI)"), 
    (3, b"Link Aggregation (deprecated)"),             
    (4, b"Maximum Frame Size"),                         
    (5, b"Energy-Efficient Ethernet"),                  
    (6, b"EEE fast wake"),                              
    (7, b"Additional Ethernet Capabilities"),           
    (8, b"Power Via MDI Measurements")
)

# Définition de variables
default_capabilities = (("MAC Bridge",0), ("Router", 1), ("WLAN Access Point", 0), ("Station Only",0))


# Définition constantes (personnelle)
TLVS = {
    'End of LLDPDU':0,               # TLV indiquant la fin d'une unité de données LLDP
    'Chassis ID':1,                  # Identifiant unique pour le châssis de l'équipement
    'Port ID':2,                     # Identifiant unique pour le port
    'Time to Live':3,                # Durée de vie du message LLDP
    'Port Description':4,            # Description textuelle du port
    'System Name':5,                 # Nom du système
    'System Description':6,          # Description du système
    'System Capabilities':7,         # Capacités du système
    'Management Address':8,          # Adresse de gestion du système
}

SYSTEM_CAP = ("Other", "Repeater", "Bridge", "WLAN Access Point", "Router", "Telephone", "DOCSIS Cable Device", "Station Only", "C-VLAN Component","S-VLAN Component", "Two-port MAC Relay", "Two-port MAC Relay")