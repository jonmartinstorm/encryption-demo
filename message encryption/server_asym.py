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

privat_nøkkel_server = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCw8wNrvknD5DSIOOAwNLv0N2lpFjMxnkW/fjBpGgjuwN/R8Q5Q\nI4bdTMXXeC3dkHd4KqHiXfvtWs8/IkRgVb9gICbF4ULCL7aLSmXQQdy3pgkpaIyj\ncAmG8Xu2xzo600LdkotfDN7/9dDm7SDTnU/FQs8EBK2u+JxoRamIdrmprwIDAQAB\nAoGABa8KOf1zqIXduBukYkTQ94m8g/WEfg04h7hs1qg3uqLAYO57Lrcz0rG8gyAA\n0FnR58hUYqbxLvd+3U2Wk6xj1SVqMf6oEdKGFlcy2scHYdgv5N7pQ3mrCSYoBx1H\nUFNkNOqqqmasboNCamOlTXJM/w2fqYEUtb1fKEhP68ZnKzUCQQDIaw6wZPejVA36\nm5vZoN/3kENk6qTr8rldSVwrq4+NlAb9ZOeqZK3r/ow5puwVKqviZn3MobD5B/Zm\ncD+tNAobAkEA4gXAD+PmCGzXwRspu1vUO0d1DPGjSvreBX2odhLoFqP3IOftMfOg\npdS7X4SegUTO7MSdn56v5yxXLrHyXl3X/QJBAIGVZuv6fHtoL5mn3z75W5Zv+oNX\ni8bbK6r7cdLynGDIIzTXd0qeyi1aakQkf2S4MGa0KgaTTR/XXCOj1CgjC50CQARM\n9bWXsYXRhF1xRd8BxU0HdAu2AVRo55aVKIJuo6nins4qe5Hqv9DH9nS/0kBFbeaF\nazZhT5mHd3U0/5aaFIUCQB7jpUnFwsTx52prhxSzE+d+VB4Pvoo7LDFVbFJB+Gnf\n1AfPyXgdV0HpcdB+2Eno9Q1fE/SZFe/aQHvT/4Jw/yM=\n-----END RSA PRIVATE KEY-----'
privat_nøkkel_server = RSA.import_key(privat_nøkkel_server)

offentlig_nøkkel_server = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw8wNrvknD5DSIOOAwNLv0N2lp\nFjMxnkW/fjBpGgjuwN/R8Q5QI4bdTMXXeC3dkHd4KqHiXfvtWs8/IkRgVb9gICbF\n4ULCL7aLSmXQQdy3pgkpaIyjcAmG8Xu2xzo600LdkotfDN7/9dDm7SDTnU/FQs8E\nBK2u+JxoRamIdrmprwIDAQAB\n-----END PUBLIC KEY-----'
offentlig_nøkkel_server = RSA.import_key(offentlig_nøkkel_server)

offentlig_nøkkel_client = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCc+3JXE0EtwLPSSeGU3udNy+8x\n3QHrxQ+G28CIP5TI0pWGjHDxQeR0vMoc5YcOil+D8FD/rLzthBIG7+eAaAdzBaLR\nGHjUzAoua3RCkVFYsorDQnF+YWLnTPGLW6Ilg/H+0nCKgPpc+HT2tmh+JcVJTU1T\nH+VUlGaDRf6kUy80oQIDAQAB\n-----END PUBLIC KEY-----'
offentlig_nøkkel_client = RSA.import_key(offentlig_nøkkel_client)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('\nConnected by', addr, '\n')
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("Fikk: ", dekrypter_asym(privat_nøkkel_server, data))
            data = krypter_asym(offentlig_nøkkel_client, dekrypter_asym(privat_nøkkel_server, data))
            conn.sendall(data)
