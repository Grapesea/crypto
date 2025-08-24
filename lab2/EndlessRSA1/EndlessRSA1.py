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
conn = remote("10.214.160.13", 12501)
data = conn.recvuntil(b'Give me XXXX (4 bytes, only contain letters or digits):')
server_message = data.decode()
print(server_message)

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

###########################################################################################
print("\033[91m这是交互第二轮\033[0m")
data = conn.recvuntil(b'@@@ m = ')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    n = int(hex_numbers[0].replace('0x', ''), 16)
    e = int(hex_numbers[1].replace('0x', ''), 16)
    c = int(hex_numbers[2].replace('0x', ''), 16)
    p = int(hex_numbers[3].replace('0x', ''), 16)
    q = int(hex_numbers[4].replace('0x', ''), 16)
    print(f"\033[91mGet key: n: {n}, e: {e}, c: {c}, p: {p}, q: {q}\033[0m")

def restore_m(n,e,c,p,q):
    phi_n = (p-1) * (q-1)
    d = gmpy2.invert(e,phi_n)
    m = pow(c,d,n)
    return m

m = restore_m(n,e,c,p,q)
print(f"\033[91m计算出m_1: {m}\033[0m")
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第三轮\033[0m")
data = conn.recvuntil(b'@@@ m = ')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    n = int(hex_numbers[0].replace('0x', ''), 16)
    e = int(hex_numbers[1].replace('0x', ''), 16)
    c = int(hex_numbers[2].replace('0x', ''), 16)
    print(f"\033[91mGet key: n: {n}, e: {e}, c: {c}\033[0m")

p = 265484613684666748942228552342347106471
q = 254697235017252043734581962613870599949

phi_n = (p-1) * (q-1)
d = gmpy2.invert(e,phi_n)
m = pow(c,d,n)
print(f"\033[91m计算出m_2: {m}\033[0m")
conn.sendline(hex(m)[2:])

# 这部分的质因数分解是用yafu工具实现的，试了几次发现n的值不变，所以大胆给p,q赋值.

###########################################################################################
print("\033[91m这是交互第四轮\033[0m")
data = conn.recvuntil(b'@@@ m = ')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    n = int(hex_numbers[0].replace('0x', ''), 16)
    e1 = int(hex_numbers[1].replace('0x', ''), 16)
    e2 = int(hex_numbers[2].replace('0x', ''), 16)
    c1 = int(hex_numbers[3].replace('0x', ''), 16)
    c2 = int(hex_numbers[4].replace('0x', ''), 16)
    print(f"\033[91mGet key: n: {n}, e1: {e1}, e2: {e2}, c1: {c1}, c2: {c2}\033[0m")

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def solve():
    g, x, y = egcd(e1, e2)
    if x < 0:
        x = -x
        c1_inv = gmpy2.invert(c1, n)
        result = pow(c1_inv, x, n)
    else:
        result = pow(c1, x, n)
    if y < 0:
        y = -y
        c2_inv = gmpy2.invert(c2, n)
        result = (result * pow(c2_inv, y, n)) % n
    else:
        result = (result * pow(c2, y, n)) % n
    return result

m = solve()
print(f"\033[91mm:{m}\033[0m")
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第五轮\033[0m")
data = conn.recvuntil(b'@@@ m = ')
server_message = data.decode()
print(server_message)
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

n = 0xce202f8fd1b78c23dfa53314617510cd422e3f4c5aa412400ed44abaf3d4bbdf4230c8f9f73736c32cbcbec0c7780b6b56f7d4bea1678640581cd4aaf2df9ff4175846fc44ddf94e924a188d0b0989ecc462da8c5e88c295e26beeafab201ab6ab299dc0f0106dd1a3cc21d17c757130be6f3f0b5b250932396f34ac3295d057
e = 0x684b3ab9779f91c23597668e5eb8dd73a3333f9fb7a456583204d255576bef204a1201d276a00cb88d531c3aa993e7304162bf673baebffc39210a1c3faa64712a4e12c1da67eb98817d981bc8bbe9d4cf605903fc039b507e8b77248a88c995741b152c41609d3d86518cba8d9da419dd36e8f8bc07881be87990ea26873b6b

if len(hex_numbers) >= 2:
    c = int(hex_numbers[2].replace('0x', ''), 16)
    print(f"\033[91mGet key: n: {n}, e: {e}, c: {c}\033[0m")
# 事实上n,e固定
 
def continued_fractions(n, d): #计算n/d的连分数展开
    fractions = []
    while d:
        q = n // d
        fractions.append(q)
        n, d = d, n - q * d
    return fractions

def convergents(cf):     # 从连分数计算收敛分数
    convergents_list = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    
    for a in cf:
        h_next = a * h_curr + h_prev
        k_next = a * k_curr + k_prev
        convergents_list.append((h_next, k_next))
        h_prev, h_curr = h_curr, h_next
        k_prev, k_curr = k_curr, k_next
    
    return convergents_list

def wiener_attack(e, N):
    cf = continued_fractions(e, N)
    convergents_list = convergents(cf)
    
    for k, d in convergents_list:
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k == 0:
            phi_candidate = (e * d - 1) // k
            
            # 尝试分解N
            # N = p*q, φ(N) = (p-1)*(q-1) = N - p - q + 1
            # 所以 p + q = N - φ(N) + 1
            s = N - phi_candidate + 1
            discriminant = s * s - 4 * N
            
            if discriminant >= 0:
                sqrt_discriminant = isqrt(discriminant)
                if sqrt_discriminant * sqrt_discriminant == discriminant:
                    p = (s + sqrt_discriminant) // 2
                    q = (s - sqrt_discriminant) // 2
                    
                    if p * q == N and p > 1 and q > 1:
                        return d, p, q
    
    return None, None, None

def small_d_attack(N, e, c):    # main
    print("Wiener攻击开始")
    d, p, q = wiener_attack(e, N)
    if d is not None:
        print(f"d = {hex(d)}")
        print(f"p = {hex(p)}")
        print(f"q = {hex(q)}")
        phi = (p - 1) * (q - 1)
        if (e * d) % phi == 1:
            m = pow(c, d, N)
            return m
    return None

m = small_d_attack(n, e, c)
print(f"\033[91mm:{m}\033[0m")
conn.sendline(hex(m)[2:])
###########################################################################################
print("\033[91m这是交互第六轮\033[0m")
data = conn.recvuntil(b'@@@ m = ')
server_message = data.decode()
print(server_message)
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    n1 = int(hex_numbers[0].replace('0x', ''), 16)
    n2 = int(hex_numbers[1].replace('0x', ''), 16)
    n3 = int(hex_numbers[2].replace('0x', ''), 16)
    e  = int(hex_numbers[3].replace('0x', ''), 16)
    c1 = int(hex_numbers[4].replace('0x', ''), 16)
    c2 = int(hex_numbers[5].replace('0x', ''), 16)
    c3 = int(hex_numbers[6].replace('0x', ''), 16)
    print(f"\033[91mGet key: n1: {n1}, n2: {n2}, n3: {n3},e: {e}, c1: {c1}, c2: {c2}, c3: {c3}\033[0m")

def CRT(n1,n2,n3,e,c1,c2,c3):
    N1 = n2 * n3
    N2 = n3 * n1
    N3 = n1 * n2
    m1 = gmpy2.invert(N1,n1)
    m2 = gmpy2.invert(N2,n2)
    m3 = gmpy2.invert(N3,n3)
    res = (c1 * m1 * N1 + c2 * m2 * N2 + c3 * m3 * N3) % (n1 * n2 * n3) # m^e % N 的结果
    print(res)
    return res

res = CRT(n1,n2,n3,e,c1,c2,c3)

def get_m(n1,n2,n3,e,c1,c2,c3,res):
    res = CRT(n1,n2,n3,e,c1,c2,c3)
    m, is_exact = gmpy2.iroot(res, e)
    print(m)
    if is_exact:
        return m
    return None

m = get_m(n1,n2,n3,e,c1,c2,c3,res)
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第七轮\033[0m")
data = conn.recvuntil(b'@@@ m = ')
server_message = data.decode()
print(server_message)
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    n    = int(hex_numbers[0].replace('0x', ''), 16)
    npnq = int(hex_numbers[1].replace('0x', ''), 16)
    e    = int(hex_numbers[2].replace('0x', ''), 16)
    c    = int(hex_numbers[3].replace('0x', ''), 16)
    print(f"\033[91mGet key: n: {n}, npnq: {npnq}, e: {e}, c: {c}\033[0m")
 
def fermat_factorization(n):
    factor_list = []
    a = gmpy2.iroot(n,2)[0]
    while True:
        a += 1
        b2 = a * a - n

        if gmpy2.is_square(b2):
            b2 = gmpy2.mpz(b2)
            b,xflag = gmpy2.iroot(b2,2)
            assert xflag
            factor_list.append([a + b, a - b])
            if len(factor_list) == 2:
                break
    return factor_list

n1 = n * npnq
factor_list = fermat_factorization(n1)
X1,Y1=factor_list[0]
X2,Y2=factor_list[1]
assert X1*Y1==n1
assert X2*Y2==n1
p_next=gmpy2.gcd(X1,X2)
q=X1//p_next
p=gmpy2.gcd(Y1,Y2)
q_next=Y1//p
print('p=',p)
print('q=',q)
print('p_next=',p_next)
print('q_next=',q_next)           # 这里使用了https://www.freebuf.com/articles/database/290623.html 的代码

def restore_m(n,e,c,p,q):
    phi_n = (p-1) * (q-1)
    d = gmpy2.invert(e,phi_n)
    m = pow(c,d,n)
    return m
m = restore_m(n,e,c,p,q)
print(f"\033[91mm:{m}\033[0m")
conn.sendline(hex(m)[2:])

###########################################################################################
print("\033[91m这是交互第八轮\033[0m")
data = conn.recvuntil(b'@@@ m = ')
server_message = data.decode()
print(server_message)
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    n    = int(hex_numbers[0].replace('0x', ''), 16)
    e    = int(hex_numbers[1].replace('0x', ''), 16)
    c    = int(hex_numbers[2].replace('0x', ''), 16)
    print(f"\033[91mGet key: n: {n}, e: {e}, c: {c}\033[0m")

def fermat_factor(n):
    for i in range(1, 1000000):
        sum , _= gmpy2.iroot(4 * n * 2019 + i**2, 2)
        if _ :
            q = (sum + i) // 2
            p = (sum - i) // 4038
            if gmpy2.is_prime(p) and gmpy2.is_prime(q):
                return p, q 
    return None, None

def restore_m(n,e,c,p,q):
    phi_n = (p-1) * (q-1)
    d = gmpy2.invert(e,phi_n)
    m = pow(c,d,n)
    return m

p,q = fermat_factor(n)
print(f"p = {p}")
print(f"q = {q}")
m = restore_m(n,e,c,p,q)
print(f"\033[91mm:{m}\033[0m")
conn.sendline(hex(m)[2:])

###########################################################################################

# 没有第九轮了，Congratulations!

conn.interactive()
conn.close()