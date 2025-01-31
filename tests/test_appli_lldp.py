#!/usr/bin/python3

import pytest
import os
import sys
from struct import pack, unpack, calcsize
sys.path.append('/home/user/s105-mohamed-kevin-soumahoro/activite_5/appli_lldp')
from lldp import *


# ************************************************************************************ #
#                                                                                      #
#               Debut Test activité 4 : Implémentation de LLDP en Python               #
#                                                                                      #
# ************************************************************************************ #

def test_get_macAddr_eth0():
    assert get_macAddr('eth0') == b'\x02\x42\x0a\xb1\x00\x02'

def test_get_macAddr_eth1():
    assert get_macAddr('eth1') == b'\x50\x00\x00\x06\x00\x01'

def test_get_macAddr_docker6_0():
    assert get_macAddr('docker6_0') == b'\x50\x00\x00\x06\x00\x00'

def test_set_lldpHeader_bridge():
    assert set_lldpHeader('eth0') == b'\x01\x80\xc2\x00\x00\x0e\x02\x42\x0a\xb1\x00\x02\x88\xcc'

def test_set_lldpHeader_notpmr():
    assert set_lldpHeader('eth0','notpmr') == b'\x01\x80\xc2\x00\x00\x03\x02\x42\x0a\xb1\x00\x02\x88\xcc'

def test_set_lldpHeader_customer():
    assert set_lldpHeader('eth0','customer') == b'\x01\x80\xc2\x00\x00\x00\x02\x42\x0a\xb1\x00\x02\x88\xcc'




def test_set_chassisTLV_eth0_mac():
    mac = get_macAddr('eth0')
    expected = b'\x02\x07\x04' + mac
    assert set_chassisTLV() == expected

def test_set_portTLV():
    mac = get_macAddr('eth1')
    expected = b'\x04\x07\x03' + mac 
    assert set_portTLV() == expected

def test_set_TTL():
    assert set_TTL() == b'\x06\x02\x00\x78'

def test_set_endLLDPDU():
    assert set_endLLDPDU() == b'\x00\x00'

def test_set_nameTLV() -> bytes:
    with os.popen("hostname") as fd :
        result = fd.readline().strip()
    hostname = result.encode('utf-8')
    length = pack('!B',len(hostname))
    tlv_type = b'\x0a'
    excepted = tlv_type + length + hostname 

    assert set_nameTLV() == excepted

def test_set_descriptionTLV():
    with os.popen("uname -srvmo") as fd :
        info_systeme = fd.readline().strip() 
    with os.popen("cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2") as fd :
        pretty_name = fd.readline().strip().strip('"')

    sys_decription = (pretty_name + ' ' + info_systeme).encode('utf-8')
    sys_decription_hex = pack('!B', len(sys_decription))
    tlv_type = b'\x0c'
    excepted = tlv_type + sys_decription_hex + sys_decription

    assert set_descriptionTLV() == excepted

def test_set_portDescriptionTLV():
    iface = 'eth1'
    port = iface.encode('utf-8')
    length_hex = pack('!B',len(iface))
    excepted = b'\x08' + length_hex + port

    assert set_portDescriptionTLV('eth1') == excepted


def test_set_capabilitiesTLV():
    tlv_type = b'\x0e'
    length = b'\x04'
    excepted = tlv_type + length + b'\x00\x9c\x00\x10'

    assert set_capabilitiesTLV() == excepted


# ***************************************************************************************** #
#                                                                                           #
#  Debut Test activité 5 : Récupération et traitement des trames d'annonces LLDP en Python  #
#                                                                                           #
# ***************************************************************************************** #

def test_get_lldpHeader():
    frame = b'\x01\x80\xc2\x00\x00\x0e\x00\x15\x5d\xad\xa9\xd7\x88\xcc'
    assert get_lldpHeader(frame) == ('01:80:c2:00:00:0e','00:15:5d:ad:a9:d7','0x88cc')

def test_get_chassisTLV():
    frame = (1, 7, b'\x04\x00\x15\x5d\x56\x43\x2b')
    assert get_chassisTLV(frame) == (b"MAC address",'00:15:5d:56:43:2b')

def test_get_portTLV():
    frame = (2, 7, b'\x03\x00\x15\x5d\x56\x43\x2b')
    assert get_portTLV(frame) == (b"MAC address", '00:15:5d:56:43:2b')

def test_get_TTL():
    frame = (3, 2, b'\x00\x78')
    assert get_TTL(frame) == 120

def test_get_endLLDPDU():
    frame = (0, 0, b'')
    assert get_endLLDPDU(frame) == ""

def test_get_sysNameTLV():
    frame = (5, 24, b'R1.chalons.univ-reims.fr')
    assert get_sysNameTLV(frame) == 'R1.chalons.univ-reims.fr'

def test_get_sysDescrTLV():
    frame = (6, 111, b'Ubuntu 22.04.5 LTS Linux 5.15.167.4-microsoft-standard-WSL2 #1 SMP Tue Nov 5 00:21:55 UTC 2024 x86_64 GNU/Linux')
    assert get_sysDescrTLV(frame) == 'Ubuntu 22.04.5 LTS Linux 5.15.167.4-microsoft-standard-WSL2 #1 SMP Tue Nov 5 00:21:55 UTC 2024 x86_64 GNU/Linux'

def test_get_portDescrTLV():
    frame = (4, 4, b'eth1')
    assert get_portDescrTLV(frame) == 'eth1'

def test_get_capabilitiesTLV():
    frame = (7, 4, b'\x00\x9c\x00\x10')
    assert get_capabilitiesTLV(frame) == (int.from_bytes(b'\x00\x9c', byteorder='big'),int.from_bytes(b'\x00\x10', byteorder='big'))



