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

nstr = b'MIGrAgEAAiEAwmNq5cPY5D'
estr = b'7l6sJAo8arGwL9s09cOvKKBv'
n = Crypto.Util.number.bytes_to_long(nstr)
e = Crypto.Util.number.bytes_to_long(estr)
print(f"n = {n}, e = {e}")
#得到 n = 28916217780919035086672137776216363791511847580546372, e = 1358960793158074254732989142681637420656766178012663857782

pq_head = "6X++MN0CAwEAAQIgGAZ5m9RM5kkSK3i0MGDHhvi3f7FZPghC2gY" # ... （残缺）
cipher = 0x1c194cd4f48d77b2e14cace43869bea17615ab23da0ef63b7bf56116ad3ac93b

pq_head_str = hashlib.base64(pq_head(encode('utf-8'))).decode()

