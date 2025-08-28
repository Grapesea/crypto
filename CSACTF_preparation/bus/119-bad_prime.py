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
from Crypto.Util.number import long_to_bytes, bytes_to_long
import sympy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

context.log_level = "debug"
conn = remote("10.214.160.13", 13333)
data = conn.recvuntil(b'Give me XXXX:')
server_message = data.decode()
print(server_message)

def string1(server_message):
    pattern = r"sha256\(XXXX\s*\+\s*([0-9a-zA-Z]+)\)\s*==\s*([0-9a-f]+)"
    match = re.search(pattern, server_message, re.IGNORECASE)

    if match:
        r = match.group(1)
        s = match.group(2)
        return r, s
    return None, None

r,s = string1(server_message)

###########################################################################################
print("\033[91m这是交互第一轮\033[0m")
print(f'Extracted: r:{r}, s:{s}')

def getxxxx(r,s):
    charset = string.ascii_letters + string.digits
    cnt = 0
    for i in range(1,7):
        for cmb in itertools.product(charset, repeat=i):
            key = ''.join(cmb)
            cnt += 1
            if (cnt % 10000000 == 0):
                print(cnt)
            if hashlib.sha256((key + r).encode()).hexdigest() == s:
                print(f"Key found: {key} after {cnt} attempts")
                return key
    return None

result = getxxxx(r,s)
print(f"找到的XXXX: {result}")
conn.sendline(result)

################################################################################
'''
Send me a cipher c so that I can calculate m=c^d modN.
Make the decrypted message using PKCS#1 V1.5 padding.
You'll get the flag as long as you show me "I am not a noob!"
c=
'''

data_buf = conn.recvuntil(b'c=')
server_message = data_buf.decode()
print(server_message)

pattern = r'N=(0x[0-9a-fA-F]+)\s+e=(0x[0-9a-fA-F]+)'
match = re.search(pattern, server_message)

if match:
    N = int(match.group(1), 16)  # 自动处理0x前缀
    e = int(match.group(2), 16)
    print(N)
    print(e)

key = RSA.construct((N, e))
cipher = PKCS1_v1_5.new(key)
msg = "I am not a noob!"
encrypted = cipher.encrypt(msg.encode())
c = bytes_to_long(encrypted)
conn.sendline(c)

conn.interactive()
conn.close()