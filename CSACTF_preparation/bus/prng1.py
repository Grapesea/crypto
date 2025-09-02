import hashlib
import itertools
import string
import re
import gmpy2
import math
import requests  # 如果在WSL中需要删掉这行
from pwn import *
import numpy as np
from math import isqrt, gcd
from fractions import Fraction
from Crypto.Util.number import long_to_bytes, bytes_to_long
import sympy
from Crypto.Cipher import AES
# from sage.all import *

# sha256(XXXX + TaikcS211CINsN29) == 85a36b62239d51bbd5970fd67a93e5984f23f96acd156a610ecb938957647a75
# Give me XXXX:

context.log_level = "debug"
conn = remote("10.214.160.13", 12600)
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
print("\033[91m这是交互第1轮\033[0m")
print(f'Extracted: r:{r}, s:{s}')

def getxxxx(r,s):
    charset = string.ascii_letters + string.digits
    cnt = 0
    for cmb in itertools.product(charset, repeat=4):
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

###########################################################################################
print("\033[91m这是交互第2轮\033[0m")




conn.interactive()
conn.close()