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

p = 960494008017250155494739990397196249930200062145145133132556398221074529657304218221253517153928380265486339083177542201148993799925721673833333778621388110957986908045712612233794551809
# x = getPrime(500)
# 已知p-1 = 2^518 * 1119326809698249181662206673457，所以看起来P-H算法更合适.
g = 3
c = 505527904713564983625416248872210831215228354175257237841602581321675204643681129570897695080321118656513647239718859773976453054734892142640867733520305568808093022238369199760987416665
ct = b'qBS\x84\xfc"\xee$\xb2d\xba\xeb\x00\xf7\xf4\xa4\x91\x90<N\x1a\xb0\xa5>\xdc^\xe3I\xc3\xecc\x1e'

p_list = [2,1119326809698249181662206673457]
por = 518 # 2的幂次

def pohlig_hellman(g, h, p, p_list, por):
    x_list = []
    for prime in p_list:
        if prime == 2:
            e = por
        else:
            e = 1
        pe = prime ** e
        g1 = pow(g, (p - 1) // pe, p)
        h1 = pow(h, (p - 1) // pe, p)
        x1 = 0
        for k in range(e):
            h2 = pow(h1 * pow(g1, -x1, p), prime ** (e - k - 1), p)
            d = 0
            while pow(g1, d * (prime ** (e - k - 1)), p) != h2:
                d += 1
            x1 += d * (prime ** k)
        x_list.append((x1, pe))
    x, mod = 0, 1
    for xi, mi in x_list:
        x += xi * mod * pow(mod, -1, mi)
        mod *= mi
    return x % mod

x = pohlig_hellman(g, c, p, p_list, por)
print(f"x = {x}")

# 跑不出来结果，哎