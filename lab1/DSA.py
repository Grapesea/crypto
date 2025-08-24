import hashlib
import itertools
import string
import re
import gmpy2
import requests 
from pwn import *

context.log_level = "debug"

def hash(text):
    return hashlib.sha256(text.encode()).hexdigest()[-6:]

def getkey(_input):
    print(_input)
    charset = string.ascii_letters + string.digits
    cnt = 0
    for i in range(1,7):
        for cmb in itertools.product(charset, repeat=i):
            key = ''.join(cmb)
            cnt += 1
            if hash(key) == _input:
                print(f"Key found: {key} after {cnt} attempts")
                return key
    return None

def hash_m(m):
    hex_hash = hashlib.sha256(m.encode()).hexdigest()
    return int(hex_hash, 16)

conn = remote("10.214.160.13", 12506)
data = conn.recvuntil(b'Give me str:')
server_message = data.decode()
print(server_message)
match = re.search(r'== ([0-9a-fA-F]{6})',server_message)
if match:
    _input = match.group(1).lower()
    print("\033[91m这是交互第一轮\033[0m")
    print(f"Get:{_input}")

result = getkey(_input)
if result:
    print(result)
    conn.sendline(result)

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

m1 = 'test'  #在这里卡了一个小时，这里必须使用解码的信息，否则永远得不到正确的答案！

def get_x(m, r1, r2, s1, s2, q):
    h = hash_m(m)
    s3 = gmpy2.invert(s1-s2, q)
    s4 = gmpy2.invert((r1-r2)*s1*s3-r1, q)
    x = (h-s1*s2*s3)*s4 % q
    return x

def get_k(m, r1, r2, s1, s2, x, q):
    h = hash_m(m)
    r1_inv = gmpy2.invert(r1, q)
    k = ((s1 * x + h) * r1_inv) % q
    return k 

x = get_x(m1, r1, r2, s1, s2, q)          
k = get_k(m1, r1, r2, s1, s2, x, q) 
y = pow(g, x, p)

print(f"Calculated x initial: {x}")
print(f"Calculated k initial: {k}")
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
m = "Plz give me the flag!"
k1 = k+1

def sign(m, x, p, q, g, k):
    h = hash_m(m)
    r = pow(g, k, p) % q
    s = gmpy2.invert(k, q) * (x * r + h) % q
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