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
    # Vi vil sjekke om vi kan stole på denne offentlige nøkkelen, om den er signert av et sertifikat vi kjenner
    signert_nøkkel = b'DJtJjPaWzhfqJZnQmwdPR2vOQr9HUWJzgRS+DNrvdh8oS6rl4ESe7uAEBmDAjvAOA6+z3VntF4P2U/4rQrr0vnG7sHqeuVAa6dbmuI7Fi8qDgz55fxL+OAxPaIvbqhbjo3GaL5uTvFa4gNitny9nLI0GQ+BC60SLPlBZCd2q340='
    offentlig_CA = RSA.import_key()
    offentlig_nøkkel = 
    
    verifisert = verifiser(offentlig_CA, offentlig_nøkkel, signert_nøkkel)
    print(f"Verifisert nøkkel?: {verifisert}")

if __name__ == '__main__':
    hovedfunksjon()