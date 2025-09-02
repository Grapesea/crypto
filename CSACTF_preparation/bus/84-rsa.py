# https://zjusec.com/challenges/84
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
import sympy

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

###########################################################################################
#Here are partial source codes:
#def sign(m, d, n):
#    return pow(bytes_to_long(m), d, n)
#
#def verify(c, e, n):
#    return 'Plz give me the flag!'  == long_to_bytes(pow(bytes_to_long(c), e, n))
###########################################################################################
m = b'Plz give me the flag!'
print(bytes_to_long(m))
conn.sendline(b'1')
data_buf = conn.recvuntil(b'Give me the msg you want to sign in hex: ') 

target = bytes_to_long(m)

conn.sendline(target)
data_buf = conn.recvuntil(b'3. Quit')
server_message = data_buf.decode()
print("\033[91mThe signature:\033[0m")
print(server_message)

s1 = re.findall(r'signature: [0-9a-f]+', server_message)
s1 = int(s1[0].replace('signature: ', ''), 16)
print(s1)



conn.interactive()
conn.close()