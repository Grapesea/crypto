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

'''
from flag import flag
assert flag.startswith("flag{")
assert flag.endswith("}")
assert len(flag)==24

def lfsr(R,mask):
    output = (R << 1) & 0xffffff  # R左移一位然后取后24bits
    i=(R&mask)&0xffffff           # R与mask与一下,然后取后24bits
    lastbit=0                     # 
    while i!=0:
        lastbit^=(i&1)
        i=i>>1                    # 求出i所有位的异或值
    output^=lastbit               # output与lastbit异或,相当于lastbit=1时最后一位取反,=0时不变
    return (output,lastbit)

def single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask):
    (R1_NEW,x1)=lfsr(R1,R1_mask)  # 
    (R2_NEW,x2)=lfsr(R2,R2_mask)
    (R3_NEW,x3)=lfsr(R3,R3_mask)
    return (R1_NEW,R2_NEW,R3_NEW,(x1*x2)^((x2^1)*x3))

R1=int(flag[5:11],16)
R2=int(flag[11:17],16)
R3=int(flag[17:23],16)
assert len(bin(R1)[2:])==17
assert len(bin(R2)[2:])==19
assert len(bin(R3)[2:])==21
R1_mask=0x10020
R2_mask=0x4100c
R3_mask=0x100002

for fi in range(1024):
    print fi
    tmp1mb=""
    for i in range(1024):
        tmp1kb=""
        for j in range(1024):
            tmp=0
            for k in range(8):
                (R1,R2,R3,out)=single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask)
                tmp = (tmp << 1) ^ out  # out是三个lastbit异或得到的值
            tmp1kb+=chr(tmp)
        tmp1mb+=tmp1kb
    f = open("./output/" + str(fi), "ab") # 打开一个文件，准备以二进制追加模式写入
    f.write(tmp1mb)
    f.close()
'''
with open("0.txt", "rb") as file:
    text_content = file.read()
num = list(text_content)
print(num)
# 251, 109, 46] 

'''
def lfsr(R,mask):
    output = (R << 1) & 0xffffff  # R左移一位然后取后24bits
    i=(R&mask)&0xffffff           # R与mask与一下,然后取后24bits
    lastbit=0                     # 
    while i!=0:
        lastbit^=(i&1)
        i=i>>1                    # 求出i所有位的异或值
    output^=lastbit               # output与lastbit异或,相当于lastbit=1时最后一位取反,=0时不变
    return (output,lastbit)

def single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask):
    (R1_NEW,x1)=lfsr(R1,R1_mask)  # 
    (R2_NEW,x2)=lfsr(R2,R2_mask)
    (R3_NEW,x3)=lfsr(R3,R3_mask)
    return (R1_NEW,R2_NEW,R3_NEW,(x1*x2)^((x2^1)*x3))
# out = (x1*x2)^((x2^1)*x3) = x1 * x3

R1=int(flagmid[5:11],16)
R2=int(flagmid[11:17],16)
R3=int(flagmid[17:23],16)
assert len(bin(R1)[2:])==17
assert len(bin(R2)[2:])==19
assert len(bin(R3)[2:])==21
R1_mask=0x10020
R2_mask=0x4100c
R3_mask=0x100002
for fi in range(1024):
    for i in range(1024):
        for j in range(1024):
            tmp=0
            for k in range(8):
                (R1,R2,R3,out)=single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask)
                tmp = (tmp << 1) ^ out  # out是三个lastbit异或得到的值， tmp每个位就是out
            num1.append(tmp)
'''

out = []








