#!/usr/bin/env python3

import socket
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5
from Crypto import Random
import base64

HOST = '127.0.0.1'  
PORT = 6543  


def krypter_asym(rsa_offentlignøkkel, klartekst):
    """
    Denne funksjonen generer ciphertekst (kryptert tekst) fra klartekst 
    (ukryptert tekst) ved hjelp av en offentlig nøkkel og returnerer en 
    base64 enkoded streng.
    """
    ciphertekst=PKCS1_OAEP.new(rsa_offentlignøkkel).encrypt(klartekst)
    b64cipher=base64.b64encode(ciphertekst)
    return b64cipher

def dekrypter_asym(rsa_privatnøkkel, b64cipher):
    """
    Denne funksjonen dekrypterer ciphertekst (kryptert tekst) til klartekst 
    (ukryptert tekst) ved hjelp av en privat nøkkel og returnerer klarteksten.
    """
    dekodet_ciphertekst = base64.b64decode(b64cipher)
    klartekst = PKCS1_OAEP.new(rsa_privatnøkkel).decrypt(dekodet_ciphertekst)
    return klartekst

privat_nøkkel_client = b'-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCc+3JXE0EtwLPSSeGU3udNy+8x3QHrxQ+G28CIP5TI0pWGjHDx\nQeR0vMoc5YcOil+D8FD/rLzthBIG7+eAaAdzBaLRGHjUzAoua3RCkVFYsorDQnF+\nYWLnTPGLW6Ilg/H+0nCKgPpc+HT2tmh+JcVJTU1TH+VUlGaDRf6kUy80oQIDAQAB\nAoGAExjVOPHRE+xti8NcX5CK1bhdi8S5tTmCuSqOVlzawB/7G/RFkJnuHYPyd/e1\nuX98nWe8qM/WJ3RRv5mLgX/WSPdV6fV1a5vOt3QKqxiriDCKLZrDtx8CgnhX/0Hw\n3fwteZZ/t2ULbpjm1QsFG2DVwPFgPsH6/DOcFM03/YEjTbkCQQC7A/fODEPeiF6p\n3JptAyZbRi6VZS+d4i9USqZi/z89oqauxLuwj26yjyRNQvsTc5ikoXCgpCELnCt/\n7faWPCQZAkEA1uNo9FNJFB/zzJ5FYYwCNsLJuznyj5vqlc6G2/M+q/R9KKqehDn9\noYN0gIqyj1azzCabwXxNPUA4l+jtcKFlyQJAZ5XPECXjAcNvC47RSkhQWoYJD164\nfS7nID0o4/SVRsJsqKj3fNg1bFm0tca/4wpIJgf1pkTCuPeLcJSR3Kz7IQJAGn/8\n53SF5Jd0J121TKxJcZtf6VjiEte1fDf15ZX/upDyBlvUJJZKMurVKSzxjD+y+JAi\nUSAVHmKXGBS/g05EEQJAbKxKUtVwcTtg00R2yQ/Q3g+uy8QecNxS6nf2kJPV5pt7\n8wcNgNQy+ES9GC6glpSimP0lWjky9S6ETHgITQ1ymQ==\n-----END RSA PRIVATE KEY-----'
privat_nøkkel_client = RSA.import_key(privat_nøkkel_client)

offentlig_nøkkel_client = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCc+3JXE0EtwLPSSeGU3udNy+8x\n3QHrxQ+G28CIP5TI0pWGjHDxQeR0vMoc5YcOil+D8FD/rLzthBIG7+eAaAdzBaLR\nGHjUzAoua3RCkVFYsorDQnF+YWLnTPGLW6Ilg/H+0nCKgPpc+HT2tmh+JcVJTU1T\nH+VUlGaDRf6kUy80oQIDAQAB\n-----END PUBLIC KEY-----'
offentlig_nøkkel_client = RSA.import_key(offentlig_nøkkel_client)

offentlig_nøkkel_server = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw8wNrvknD5DSIOOAwNLv0N2lp\nFjMxnkW/fjBpGgjuwN/R8Q5QI4bdTMXXeC3dkHd4KqHiXfvtWs8/IkRgVb9gICbF\n4ULCL7aLSmXQQdy3pgkpaIyjcAmG8Xu2xzo600LdkotfDN7/9dDm7SDTnU/FQs8E\nBK2u+JxoRamIdrmprwIDAQAB\n-----END PUBLIC KEY-----'
offentlig_nøkkel_server = RSA.import_key(offentlig_nøkkel_server)

kryptert_melding = krypter_asym(offentlig_nøkkel_server, b'Hello, world')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(kryptert_melding)
    data = s.recv(1024)

klartekst = dekrypter_asym(privat_nøkkel_client, data)

print('\nReceived', klartekst, '\n')