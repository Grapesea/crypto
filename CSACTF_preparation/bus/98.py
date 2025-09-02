# https://zjusec.com/challenges/84
import hashlib
import itertools
import string
import re
import gmpy2
import math
from pwn import *
import numpy as np
from math import isqrt, gcd
from fractions import Fraction
from Crypto.Util.number import bytes_to_long, long_to_bytes
import sympy
# from sage.all import *
import subprocess

context.log_level = "debug"
conn = remote("10.214.160.13", 12601)
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
print("\033[91m这是交互第1轮\033[0m")
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

###########################################################################################
print("\033[91m这是交互第2轮\033[0m")

data = conn.recvuntil(b'm = ')
server_message = data.decode()
print(server_message)
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    e = int(hex_numbers[0].replace('0x', ''), 16)
    n1 = int(hex_numbers[1].replace('0x', ''), 16)
    c1 = int(hex_numbers[2].replace('0x', ''), 16)
    n2  = int(hex_numbers[3].replace('0x', ''), 16)
    c2 = int(hex_numbers[4].replace('0x', ''), 16)
    n3 = int(hex_numbers[5].replace('0x', ''), 16)
    c3 = int(hex_numbers[6].replace('0x', ''), 16)
    print(f"\033[91mGet key: n1: {n1}, n2: {n2}, n3: {n3},e: {e}, c1: {c1}, c2: {c2}, c3: {c3}\033[0m")

def CRT(n1,n2,n3,c1,c2,c3):
    N1 = n2 * n3
    N2 = n3 * n1
    N3 = n1 * n2
    m1 = gmpy2.invert(N1,n1)
    m2 = gmpy2.invert(N2,n2)
    m3 = gmpy2.invert(N3,n3)
    res = (c1 * m1 * N1 + c2 * m2 * N2 + c3 * m3 * N3) % (n1 * n2 * n3) # m^e % N 的结果
    return res

res = CRT(n1,n2,n3,c1,c2,c3)

def get_m(n1,n2,n3,e,c1,c2,c3,res):
    res = CRT(n1,n2,n3,c1,c2,c3)
    m, is_exact = gmpy2.iroot(res, e)
    
    if is_exact:
        print("\033[91mm:\033[0m")
        print(m)
        return m
    return None

m = get_m(n1,n2,n3,e,c1,c2,c3,res)
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第3轮\033[0m")
data = conn.recvuntil(b'm = \n')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

e = 6
p = 7717066755183648316971940602368361227644774808731164979571528743992335442501560948603930672266471830003737452875482057062262403880366285902367115868141827
q = 11590696112448483436527762795820583914877913656258503544939159374864561102531454478960117863311890030366057906019922669489356324662093723730430974940956001
n = p*q
if len(hex_numbers) >= 2:
    c = int(hex_numbers[3].replace('0x', ''), 16)
    print(f"\033[91mGet c: {c}\033[0m")

# print(gmpy2.gcd(e,p-1), gmpy2.gcd(e,q-1))  2,2
d_ = gmpy2.invert(3,(p-1)*(q-1))
res = pow(c,d_,n)
m = gmpy2.iroot(res,2)[0]
print(m)

conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第4轮\033[0m")
data = conn.recvuntil(b'm = ')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)

if len(hex_numbers) >= 2:
    c = int(hex_numbers[2].replace('0x', ''), 16)
    print(f"\033[91mGet c: {c}\033[0m")
n = 0x4a471ffda8b4d8d223f6b64884b798a8a8356e6d024f92c46a9171c8841b
e = 3

p = 800336709776908303691579 # pow = 1
q = 800336709776908303690799 # pow = 2

phi = (p-1)*(q-1)*q
d = gmpy2.invert(e,phi)
m = pow(c,d,n)

print(m)
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第4轮\033[0m")
data = conn.recvuntil(b'm = ')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)

if len(hex_numbers) >= 2:
    c = int(hex_numbers[3].replace('0x', ''), 16)
    print(f"\033[91mGet c: {c}\033[0m")

n = 0x81a8a5d31d394cf22be1279821b393cf40fc50bfee4720c5a37d4adcca081733d4386a528d156db3c8e9a464c1d16057e656af4fd9b23ec162b2732758646f62c7349ddf384d415b177e7e4f9177d381da8ba389ea19c86baad6d4e18095cdb8221117260d7bb790bc8b5a8902022dc4f4614be72709d382be0f185ed474805b
e = 65537
dp = 0x46b50ee343445e826f0405f22a61902efeed47dd29e69b351ccb0e7d6377981c29dc6277a98934375f50de7309299fe92772110f855ee0d3af948185ee473c17
# assert dp == d%(p-1)
# assert c == pow(m, e, n)

p = 7010173429825364096483198373148695080777600230634223905598006877008362970389922446515938798609891083009103950216075939132993276370895055486168201663192527
q = 12988193913131624476685175811562898160517888405838841061588955125010438953846498671738108261014900926212870350440269819634930731186959088388206550178956213

phi = (p-1)*(q-1)
d = gmpy2.invert(e,phi)
m = pow(c,d,n)
print(m)
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第5轮\033[0m")
data = conn.recvuntil(b'your choice: \n')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)
n = int(hex_numbers[0].replace('0x', ''), 16)
print(f"\033[91mGet n: {n}\033[0m")

conn.sendline(hex(1)[2:])
data = conn.recvuntil(b'your k(hex): \n')

# result = 0x---------- 
conn.sendline(hex(1)[2:])
data = conn.recvuntil(b'your choice: \n')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)
result1 = int(hex_numbers[0].replace('0x', ''), 16)
print(f"\033[91mGet result1: {result1}\033[0m")

conn.sendline(hex(1)[2:])
data = conn.recvuntil(b'your k(hex): \n')

conn.sendline(hex(2)[2:])
data = conn.recvuntil(b'your choice: \n')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)
result2 = int(hex_numbers[0].replace('0x', ''), 16)
print(f"\033[91mGet result2: {result2}\033[0m")

sage_code = f"""
import json
n = {n}
res1 = {result1}
res2 = {result2}
def related_message_attack(res1, res2, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^2 + x - res1
    g2 = x^4 + 4*x^3 + 4*x^2 - res2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]

ans = int(related_message_attack(res1, res2, n))
print("FINAL_RESULT:")
print(int(ans))
"""

sage_path = "/usr/bin/sage"
result = subprocess.run(
        [sage_path, '-c', sage_code],
        capture_output=True,
        text=True,
        timeout=30
    )
    
if result.returncode == 0:
        # 直接读取 SageMath 的输出（整数）
    lines = result.stdout.strip().split('\n')
    for line in lines:
        if line.startswith('FINAL_RESULT:'):
            continue
        try:
            m = int(line.strip())
            print(f"Found result: {m}")
            break
        except ValueError:
            continue
else:
    print(f"\033[91mFailed!!!!!!!!!!\033[0m")

conn.sendline(hex(2)[2:])
data = conn.recvuntil(b'm = \n')
server_message = data.decode()
print(server_message)
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第6轮\033[0m")
# python3 98.py


conn.interactive()
conn.close()