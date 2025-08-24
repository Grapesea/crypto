from Crypto.Util.number import *

def related_message_attack(c1, c2, t, e, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+t)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]

p, q = getPrime(512), getPrime(512)
n = p * q
e = 13
m = bytes_to_long(b'flag{this_is_a_sample_flag}')
t = getPrime(1024)

c1 = pow(m, e, n)
c2 = pow(m+t, e, n)

print(long_to_bytes(ZZ(related_message_attack(c1, c2, t, e, n))))
