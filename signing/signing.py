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
    pn, on = rsanøkler()
    tekst = b"Hei hele TBB!"
    print("\nTekst: " + tekst.decode('utf-8'))

    print("\nKrypterer")
    ct = krypter(on, tekst)
    print("Ciphertekst: " + ct.decode('utf-8'))

    print("\nDekrypterer")
    dt = dekrypter(pn, ct)
    print("Dekryptert: " + dt.decode('utf-8'))
    print()

    print("\nSignerer")
    signert = signer(pn, tekst)
    print("Signert tekst: " + signert.decode())

    print("\nVerifiserer")
    verifisert = verifiser(on, tekst, signert)
    print(f"Verifisert?: {verifisert}")

    # private keys for the public ones in sertifikat.md
    pkeyserv = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCiydJYN0nxa0teuYC/jntQq5EQ8fHUAv2hjtOeWtqK8alQgvbh\ngBO6wQKzUAVKlD7xFNoJqVC6wasrzS8v1g2TwmgV1cR6ELH96G3agvbWrqaAbLHN\n3sIkkrpfNrUcP8PKjncjVNX4RwTFXI5dgny1nfiu6KiCvXsUZilmtd2O0QIDAQAB\nAoGAH9CKRbfegWp7AzMFbMqToqc5NYLXhJwmBhRUGut+MS/8K3JA/j7J/FJ67OD7\ne8Ef0P2GhGNdFfbCNZAHBBYVNmbx+laAY3UhGU5T5YQvFKi8/WAajSQT7uiwVK6k\nG/LJj3hD9TWQTSUiRah1LN6eO8p9oxtFKj9UwgFF9rIiQZ0CQQDGomeOXMaHds9e\nas6X9amsyUDbNTEavmIQ3VemOfAP77SKee1Vqto9ZYp1Pm1BVQEHCY7h+66NEqUN\nLH52Iv09AkEA0c04YqSbnboSQPmUraCQ85SaVTto1OHgfErNJxAx3DjgOo4tkRbT\nhFReFM+vQrJxXQmvoBiGK2GOwwFVwaQZJQJBAMLDk06f4XoKISKvD4sosgpd+131\nNgTHEFkA72RqAt1daGUvUGtjb0IsQirb3zzkIHHKCXPD2E8zLOtR6V3kyPECQEoW\nRU4YQNfPCHknaYhyxh0uId3tT9S1OxfJNm8P+fuBnjUvVgoBXIpDXMHOoV5VM1Ee\nhYVsg5y4I7jbNNRfxX0CQQCeg9aQMHr0KTvGQGyvr9WHiYfGp+E0jRIiahM07VNx\nPNdBPVLXEzsgphaAOF5zOqqhTjUvNujw7b65qmO+Cw33\n-----END RSA PRIVATE KEY-----'
    pkeyserv = RSA.import_key(pkeyserv)
    hash = b'bf35f93df686f28ea3aa7cbf4f7f4a5c'
    signert_hash = signer(pkeyserv, hash)
    print(f"Signert tekst: {signert_hash}")

    pkeyca = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC1t9mPQDvMdYOtkMOVvoLa/Le7uLsjrSUjZ7tF+Xlg6m9qzgvv\nY282p0l4FYIovkQVTkUNVlRG8WebramAL7ZotWKnT4COhqHTHLyTi/IWzP6APHUI\nY+FuWQCUd0qL3dcZUNMn5Wc+MZuVmdYvfU8T55UrkxLCADhp9rbfnbLwlQIDAQAB\nAoGADMMXXx1+avhAgeAOMbtqKpcKZaoDpUMeaJjQaN8BzJyqVoXssKilwYuIzWDf\n/fHe4OAuWVFxecoFIhnViFB8LvVm/HhdTQKhQn84UyBlsS3FVb49tn5GR+XjrN7x\nH89NsHIwzBT2F7ehkh/3KNvZIFnJD9orj3DyJqW+xOCcbAECQQDPN6PHOoAzK8i8\n0ZFRnzZhWmtl/g2exG1yPMhEh4NpJ9TNJyV1Ovp9WcphV82JGrt0E1r4NsG4S9n5\nXcCE0YZxAkEA4H9zsr4xVVZPwvytM06i0s5OL9uS32WiMJPimOraJ/57/h1sBKsd\nRIAjiKnLY+1dCRVNT3ivfh7dkRHuL6ZGZQJAXBKc8ylLTXFnAH8d0uargxZqIieA\nZcth1iCr28da3J6WL5H1UuGh65C6HAanjQQTxr/S6/donDsX33WI1XtEAQJAXobr\n5YhV53PXU+fm2eKzhoXdwCL5Xd1ChKfQUskYoJx0AxTKZdDTGwPFcobkIChS8z8n\n9V2Ar185thrRqvidTQJBAKtmBE6CPX0hw+zZ8ues/EvRM64LsLCyAUS3Z3KVgg4F\nQ3wnLO/xUvY38NRhIXLC98mFAQ+iYH5Uv4OqzzSnHn8=\n-----END RSA PRIVATE KEY-----'
    pkeyca = RSA.import_key(pkeyca)
    offkeyserv = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiydJYN0nxa0teuYC/jntQq5EQ\n8fHUAv2hjtOeWtqK8alQgvbhgBO6wQKzUAVKlD7xFNoJqVC6wasrzS8v1g2TwmgV\n1cR6ELH96G3agvbWrqaAbLHN3sIkkrpfNrUcP8PKjncjVNX4RwTFXI5dgny1nfiu\n6KiCvXsUZilmtd2O0QIDAQAB\n-----END PUBLIC KEY-----'
    signert_hash = signer(pkeyca, offkeyserv)
    print(f"Signert nøkkel: {signert_hash}")

if __name__ == '__main__':
    hovedfunksjon()