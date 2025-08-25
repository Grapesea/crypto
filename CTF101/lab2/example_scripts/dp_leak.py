from Crypto.Util.number import *
from gmpy2 import *

m = bytes_to_long(b'flag{this_is_a_sample_flag}')
p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p-1)*(q-1)
e = 65537
d = invert(e,phi)
dp = d%(p-1)
c = pow(m,e,n)

for k in range(1,e):
    if (e * dp - 1) % k != 0:
        continue
    pp = (e * dp - 1) // k + 1
    if n % pp != 0:
        continue
    qq = n // pp
    phi = (pp-1)*(qq-1)
    d = invert(e, phi)
    print(long_to_bytes(pow(c, d, n)))
    break
