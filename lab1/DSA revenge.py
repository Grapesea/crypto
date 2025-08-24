import hashlib
import itertools
import string
import re
import gmpy2
import requests 
from pwn import *

''' 第一次交互的内容：
Here comes your challenge:
sha256(XXXX + 8sR5kmZEhCr9EFUe) == fe82db438bf7e732c63467aa0e8bdbdc153cf1a17eddad260d729c27fb892f08
Give me XXXX:
'''
context.log_level = "debug"
conn = remote("10.214.160.13", 12710)
data = conn.recvuntil(b'Give me XXXX:')
server_message = data.decode()
print(server_message)

def string1(server_message):
    pattern = r'sha256\(XXXX\s*\+\s*([0-9a-zA-Z]+)\)\s*==\s*([0-9a-f]+)'
    match = re.search(pattern, server_message, re.IGNORECASE)

    if match:
        r = match.group(1)
        s = match.group(2)
        return r, s
    return None, None

r,s = string1(server_message)
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
print("\033[91m这是交互第二轮\033[0m")

data_buf = conn.recvuntil(b'4. Quit\n')  #这个参数没什么用，留下作为缓冲
conn.sendline(b'3')
data2 = conn.recvuntil(b'4. Quit\n')
server_message = data2.decode()
print(server_message)

hex_numbers = re.findall(r'0x[0-9a-f]+L', server_message) # 使用findall找到所有16进制数

if len(hex_numbers) >= 2:
    p = int(hex_numbers[0].replace('0x', '').replace('L', ''), 16)
    q = int(hex_numbers[1].replace('0x', '').replace('L', ''), 16)
    g = int(hex_numbers[2].replace('0x', '').replace('L', ''), 16)
    print(f"Get publickey: p: {p}, q: {q}, g: {g}")

def parse_signature(server_message):
    pattern = r'signature:\s*([0-9a-f]+)\s*,\s*([0-9a-f]+)'
    match = re.search(pattern, server_message, re.IGNORECASE)

    if match:
        r = int(match.group(1), 16)
        s = int(match.group(2), 16)
        return r, s
    return None, None

conn.sendline(b'1')
data_buf = conn.recvuntil(b'Give me the msg you want to sign in hex: ') 
conn.sendline(b'74657374')     # 这个是test的Hex
data_buf = conn.recvuntil(b'4. Quit')
server_message = data_buf.decode()
print("\033[91mThe 1st signature:\033[0m")
print(server_message)
r1, s1 = parse_signature(server_message)
print(f'r1 ={r1} s1 = {s1}')

conn.sendline(b'1')
data_buf = conn.recvuntil(b'Give me the msg you want to sign in hex: ')
conn.sendline(b'74657374')     # 这个是test的Hex
data_buf = conn.recvuntil(b'4. Quit')
server_message = data_buf.decode()
print("\033[91mThe 2nd signature:\033[0m")
print(server_message)
r2, s2 = parse_signature(server_message)
print(f'r2 ={r2} s2 = {s2}')

conn.sendline(b'2') 
data_buf = conn.recvuntil(b'Give me the signature you want to verify in hex (split with a space): ')

m1 = 'test'
def hash_m(m):
    hex_hash = hashlib.sha256(m.encode()).hexdigest()
    return int(hex_hash, 16)
a = int('0x114514191981011451419198101145141919810114514',16)
b = 114514191981011451419198101145141919810114514
c = int('0x461dfd2563cd550adcf9882229c456078d62a4cf83cc69e91264ae5de1c3a6be4078c27eb7b7d68d',16)
# k = (ak+b) % c
# k_bar = k >> 160  

def get_kbar(m, r1, s1, r2, s2, q, a, b, c):
    h = hash_m(m)
    ma = min(c//a, q)
    for k in range(ma):
        if ( k % 10000000 == 0):
            print(f"Trying k: {k}")
        t = (a * k + b) % c >> 160
        left = (r2*s1*k-r1*s2*t) % q
        right = h*(r2-r1) % q
        if (left == right):
            print("\033[91mGet k!\033[0m")
            return k 
    return None

def get_x(m, r1, s1, q, k):
    h = hash_m(m)
    x = (k*s1-h)*gmpy2.invert(r1,q) % q
    return x  
        
k = get_kbar(m1, r1, s1, r2, s2, q, a, b, c)
if k is None:
    print("\033[91mFailed to find k\033[0m")

x = get_x(m1, r1, s1, q, k)

# 整道题的核心就在计算k,x上了
y = pow(g, x, p)

print(f"Calculated y initial: {y}")

def verify(m, r, s, y, p, q, g):
    h = hash_m(m)
    u = gmpy2.invert(s, q) * h
    v = gmpy2.invert(s, q) * r
    return pow(g, u, p) * pow(y, v, p) % p % q == r
flag = verify(m1, r1, s1, y, p, q, g)
if flag:
    print(f"Calculated x last: {x}")
    print(f"Calculated k last: {k}")
else:
    print("\033[91mFailed\033[0m")
m = "Plz give me the flag again!"
k1 = (a * k + b) % c

def sign(m, x, p, q, g, k):
    h = hash_m(m)
    k0 = k >> 160
    r = pow(g, k0, p) % q
    s = gmpy2.invert(k0, q) * (x * r + h) % q
    return r, s

def signature(r, s):
    r_hex = f"{r:x}"
    s_hex = f"{s:x}"
    return f"{r_hex} {s_hex}"

r,s = sign(m, x, p, q, g, k1)
verify_result = signature(r,s)

conn.sendline(verify_result)  
conn.interactive()
conn.close()