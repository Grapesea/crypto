import hashlib
import itertools
import string
import re
import gmpy2
import math
import requests 
from pwn import *
import numpy as np
from math import isqrt, gcd
from fractions import Fraction
from Crypto.Util.number import bytes_to_long, long_to_bytes

IP = "10.214.160.13"
PORT = 12900

context.log_level = "debug"
conn = remote("10.214.160.13", 12505)
data = conn.recvuntil(b'Give me str:')
server_message = data.decode()
print(server_message)

# sha256(str).hexdigest()[-6:] == 6f3d80

def string1(server_message):
    pattern = r"sha256\(str\)\.hexdigest\(\)\[-6:\]\s*==\s*([0-9a-f]+)"
    match = re.search(pattern, server_message, re.IGNORECASE)

    if match:
        r = match.group(1)
        return r
    return None

r = string1(server_message)

print(f'Extracted: {r}')

def get(r):
    charset = string.ascii_letters + string.digits
    cnt = 0
    for i in range(1,7):
        for cmb in itertools.product(charset, repeat=i):
            key = ''.join(cmb)
            cnt += 1
            if (cnt % 10000000 == 0):
                print(cnt)
            if hashlib.sha256((key).encode()).hexdigest()[-6:] == r:
                print(f"Key found: {key} after {cnt} attempts")
                return key
    return None

result = get(r)
print(f"找到key: {result}")
conn.sendline(result)

m = b'test'
ms = bytes_to_long(m)
print(ms)
# ms = 1952805748
conn.sendline(b'1')
data_buf = conn.recvuntil(b'Give me the msg you want to sign in hex: ') 
conn.sendline(hex(ms)[2:].encode())
data_buf = conn.recvuntil(b'3. Quit\n')
server_message = data_buf.decode()
print(server_message)

def string2(server_message):
    pattern = r"Here is your signature:\s*([a-f0-9]+)"
    match = re.search(pattern, server_message, re.IGNORECASE)

    if match:
        r = match.group(1)
        return r
    return None

r = string2(server_message)
print(f'Extracted: {r}')


conn.interactive()
conn.close()