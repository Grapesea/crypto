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
import Crypto.Util.number
import sympy

context.log_level = "debug"
conn = remote("10.214.160.13", 12503)
data = conn.recvuntil(b'Give me XXXX (4 bytes, only contain letters or digits):')
server_message = data.decode()
print(server_message)
'''
sha256(XXXX + '1StjL8').hexdigest() == 5d26be5feb852708a64c53d03b5d7b16b254ea01d732b44f047b7c74809585c0
Give me XXXX (4 bytes, only contain letters or digits):
'''

def string1(server_message):
    pattern = r"sha256\(XXXX\s*\+\s*'([0-9a-zA-Z]+)'\)\.hexdigest\(\)\s*==\s*([0-9a-f]+)"
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



conn.interactive()
conn.close()