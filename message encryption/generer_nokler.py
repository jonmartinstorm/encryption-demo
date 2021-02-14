#!/usr/bin/env python3

import socket
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5
from Crypto import Random
import base64

def rsanøkler():
    """
    Denne funksjonen lager en privat nøkkel og en offentlig nøkkel
    """
    lengde=1024  
    privatnøkkel = RSA.generate(lengde, Random.new().read)  
    offentlignøkkel = privatnøkkel.publickey()  
    return privatnøkkel, offentlignøkkel

def hovedfunksjon():
    pn, on = rsanøkler()
    print(pn.export_key())
    print()
    print(on.export_key())

if __name__ == '__main__':
    hovedfunksjon()