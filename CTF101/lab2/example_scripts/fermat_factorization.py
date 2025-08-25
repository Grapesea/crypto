from Crypto.Util.number import *
from gmpy2 import *
from sympy import nextprime

p = getPrime(1024)
q = nextprime(p)
n = p * q
e = 65537
m = bytes_to_long(b'this_is_a_flag')
c = pow(m, e, n)

def solve(a, b, c):
    delta = b*b - 4*a*c
    if delta < 0:
        return (0,0)
    delta = isqrt(delta)
    if (-b + delta) % (2 * a) != 0 and (-b - delta) % (2 * a) != 0:
        return (0, 0)
    return ((-b + delta) // (2 * a),(-b - delta) // (2 * a))

for i in range(1000):
    tmp = i**2+4*n
    if iroot(tmp, 2)[1]:
        p,q = solve(1, -iroot(tmp, 2)[0], n)
        phi = (p-1)*(q-1)
        d = invert(e, phi)
        print(long_to_bytes(pow(c, d, n)))

