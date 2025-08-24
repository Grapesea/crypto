from Crypto.Util.number import *
from gmpy2 import *

def exgcd(a,b):
    if b == 0:
        return a, 0
    tempx, tempy = exgcd(b, a % b)
    x = tempy
    y = tempx - a // b * tempy
    return x, y

m = bytes_to_long(b'flag{this_is_a_sample_flag}')
p = getPrime(512)
q = getPrime(512)
n = p * q
e1 = 2519901323
e2 = 3676335737
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)

s1, s2 = exgcd(e1, e2)
if s1 < 0:
    s1 = -s1
    c1 = invert(c1, n)
if s2 < 0:
    s2 = -s2
    c2 = invert(c2, n)

print(long_to_bytes(pow(c1, s1, n)*pow(c2, s2, n)%n))
