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
from collections import defaultdict
from Crypto.Cipher import AES


'''
p = 960494008017250155494739990397196249930200062145145133132556398221074529657304218221253517153928380265486339083177542201148993799925721673833333778621388110957986908045712612233794551809
# x = getPrime(500)
# 已知p-1 = 2^518 * 1119326809698249181662206673457，所以看起来P-H算法更合适.
n = p-1
g = 3
h = 505527904713564983625416248872210831215228354175257237841602581321675204643681129570897695080321118656513647239718859773976453054734892142640867733520305568808093022238369199760987416665
ct = b'qBS\x84\xfc"\xee$\xb2d\xba\xeb\x00\xf7\xf4\xa4\x91\x90<N\x1a\xb0\xa5>\xdc^\xe3I\xc3\xecc\x1e'
'''

'''
xi_list = [0 for i in range(518)]
po = 517
def getx(g,h,n):
    n_ = n // 2
    h_ = h
    hi = pow(h_,n_,p)
    if hi == 1 : # x[0] == 0
        xi_list.append(0)
    else:
        xi_list.append(1)
    for i in range(1,518):
        n_ /= 2
        h_ *= pow(gmpy2.invert(g,p),xi_list[i-1],p)
        hi = pow(h_,n_,p)
        if hi == 1 : # x[i] == 0
            xi_list.append(0)
        else:
            xi_list.append(1)


x10 = 0
for i in range(518):
    x10 += 2**i * xi_list[i]
print(xi_list)
print(x10)

p2 = 1119326809698249181662206673457
g20 = pow(g,2**518,p)
h20 = pow(h,2**518,p)
x20 = 0

for i in range(p2):
    if (pow(g20, i, p) == h20):
        x20 = i
        print(f"找到x20:{x20}")
'''

p = 960494008017250155494739990397196249930200062145145133132556398221074529657304218221253517153928380265486339083177542201148993799925721673833333778621388110957986908045712612233794551809
n = p - 1
g = 3
h = 505527904713564983625416248872210831215228354175257237841602581321675204643681129570897695080321118656513647239718859773976453054734892142640867733520305568808093022238369199760987416665
ct = b'qBS\x84\xfc"\xee$\xb2d\xba\xeb\x00\xf7\xf4\xa4\x91\x90<N\x1a\xb0\xa5>\xdc^\xe3I\xc3\xecc\x1e'

# 计算 x mod 2^518
x = 0  # 累计值
gamma = pow(g, n // 2, p)  # γ = g^(n/2) mod p，阶为2

for k in range(518):
    exponent = n // (2 ** (k + 1))  # 整数除法
    h_k = (h * pow(g, -x, p)) % p  # 调整 h
    temp = pow(h_k, exponent, p)
    if temp == 1:
        x_k = 0
    elif temp == gamma:
        x_k = 1
    else:
        print(f"Error at k={k}")
        x_k = 0
    x += x_k * (2 ** k)

print(f"x = {x}")
assert (pow(g,x,p) == h)

key = hashlib.md5(str(x).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(ct) # 解密
flag = decrypted.rstrip(b'\x00')  # 去除填充的空字节

print(f"Flag: {flag.decode()}")