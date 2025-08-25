from Crypto.Util.number import *
from gmpy2 import *

p = getPrime(512)
q = getPrime(512)
n = p * q
m = bytes_to_long(b'this_is_a_sample_flag')
e = 3
c = pow(m, e, n)

print(long_to_bytes(iroot(c,3)[0]))



m = bytes_to_long(b'this_is_a_sample_flaggggggggggggggggggggggg')
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 3
c = pow(m, e, n)

for k in range(1000000):
    tmp = c + k * n
    if iroot(tmp, 3)[1]:
        print(long_to_bytes(iroot(tmp, 3)[0]))
        break