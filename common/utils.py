import random
import time
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def random_ticket_lifetime(min_sec=1, max_sec=5):
    return random.randint(min_sec, max_sec)

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + chr(pad_len) * pad_len

def unpad(data):
    pad_len = ord(data[-1])
    return data[:-pad_len]

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    json_data = json.dumps(data)
    padded_data = pad(json_data).encode()
    return cipher.encrypt(padded_data)

def decrypt(key, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(enc).decode()
    return json.loads(unpad(decrypted))

def gen_key():
    return get_random_bytes(16)

def now():
    return int(time.time())
