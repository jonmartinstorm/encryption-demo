#!/usr/bin/env python3

import socket
import hashlib
import math
import os

from Crypto.Cipher import AES

HOST = '127.0.0.1'  
PORT = 6543       
IV_SIZE = 16    # 128 bit, fixed for the AES algorithm
KEY_SIZE = 32   # 256 bit meaning AES-256, can also be 128 or 192 bits
SALT_SIZE = 16  # This size is arbitrary

def krypter_sym(melding, passord):
    salt = os.urandom(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac('sha256', passord, salt, 100000, dklen=IV_SIZE + KEY_SIZE)
    iv = derived[0:IV_SIZE]
    key = derived[IV_SIZE:]
    return salt + AES.new(key, AES.MODE_CFB, iv).encrypt(melding)

def dekrypter_sym(melding, passord):
    salt = melding[0:SALT_SIZE]
    derived = hashlib.pbkdf2_hmac('sha256', passord, salt, 100000, dklen=IV_SIZE + KEY_SIZE)
    iv = derived[0:IV_SIZE]
    key = derived[IV_SIZE:]
    return AES.new(key, AES.MODE_CFB, iv).decrypt(melding[SALT_SIZE:])

passord = b'highly secure encryption password'

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
            print("Fikk: ", dekrypter_sym(data, passord))
            conn.sendall(data)
