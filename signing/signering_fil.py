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

def krypter(rsa_offentlignøkkel, klartekst):
    """
    Denne funksjonen generer ciphertekst (kryptert tekst) fra klartekst 
    (ukryptert tekst) ved hjelp av en offentlig nøkkel og returnerer en 
    base64 enkoded streng.
    """
    ciphertekst=PKCS1_OAEP.new(rsa_offentlignøkkel).encrypt(klartekst)
    b64cipher=base64.b64encode(ciphertekst)
    return b64cipher

def dekrypter(rsa_privatnøkkel, b64cipher):
    """
    Denne funksjonen dekrypterer ciphertekst (kryptert tekst) til klartekst 
    (ukryptert tekst) ved hjelp av en privat nøkkel og returnerer klarteksten.
    """
    dekodet_ciphertekst = base64.b64decode(b64cipher)
    klartekst = PKCS1_OAEP.new(rsa_privatnøkkel).decrypt(dekodet_ciphertekst)
    return klartekst

def signer(rsa_privatnøkkel, data):
    """
    Denne funksjonen signerer data med en privat nøkkel 
    """
    hashet_data = MD5.new(data)
    signert_data = pkcs1_15.new(rsa_privatnøkkel).sign(hashet_data)
    b64_data = base64.b64encode(signert_data)
    return b64_data

def verifiser(rsa_offentlignøkkel,data,signert_data):
    """
    Denne funksjonen verifiserer at data er signert med en privat nøkkel 
    """
    hashet_data = MD5.new(data)
    signert_data = base64.b64decode(signert_data)
    try:
        pkcs1_15.new(rsa_offentlignøkkel).verify(hashet_data, signert_data)
        return True
    except ValueError:
        return False


def hovedfunksjon():
    # Vi har fått en fil og en signert hash
    signert_hash = b'OGzUeaV6Glj9aARxZp46ch4fhkVegmPfx5rIwqBwZXlYBP0UXm2IyXALIiXmOaUkESjDMrZCB02sgLAzMXA8i2zN0/HM5auLYd8UNjaOLnSp9+CoJ3NCAZDEWEjE//qoHzBlDDFzbdKeSNVarFcECKlzVrt4HtxQK8Gvd0gR+Uk='
    
    vår_hash = b'bf35f93df686f28ea3aa7cbf4f7f4a5c'
    offentlig_nøkkel = RSA.import_key(b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiydJYN0nxa0teuYC/jntQq5EQ\n8fHUAv2hjtOeWtqK8alQgvbhgBO6wQKzUAVKlD7xFNoJqVC6wasrzS8v1g2TwmgV\n1cR6ELH96G3agvbWrqaAbLHN3sIkkrpfNrUcP8PKjncjVNX4RwTFXI5dgny1nfiu\n6KiCvXsUZilmtd2O0QIDAQAB\n-----END PUBLIC KEY-----')

    verifisert = verifiser(offentlig_nøkkel, vår_hash, signert_hash)
    print(f"Verifisert?: {verifisert}")


if __name__ == '__main__':
    hovedfunksjon()