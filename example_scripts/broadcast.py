from Crypto.Util.number import *
from gmpy2 import *

def CRT(a, b):
    pro = 1
    res = 0
    for i in b:
        pro *= i
    for i in range(len(b)):
        r = pro // b[i]
        res += a[i] * r * invert(r, b[i])
    return res % pro, pro

m=bytes_to_long(b'flag{this_is_a_sample_flagggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg')

p1 = getPrime(512)
q1 = getPrime(512)
n1 = p1 * q1

p2 = getPrime(512)
q2 = getPrime(512)
n2 = p2 * q2

p3 = getPrime(512)
q3 = getPrime(512)
n3 = p3 * q3

e = 3

c1 = pow(m, e, n1)
c2 = pow(m, e, n2)
c3 = pow(m, e, n3)

c, n = CRT([c1,c2,c3],[n1,n2,n3])

for k in range(10000000):
    tmp = c + k * n
    judge = iroot(tmp, 3)
    if iroot(tmp, 3)[1]:
        print(long_to_bytes(iroot(tmp, 3)[0]))
        break
