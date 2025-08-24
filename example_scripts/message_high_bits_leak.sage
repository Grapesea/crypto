from Crypto.Util.number import *
from random import randint

p, q = getPrime(512), getPrime(512)
n, e = p * q, 3
m = randint(0, n)
c = pow(m ,e, n)
m_high = m >> 300

P.<x> = PolynomialRing(Zmod(n))
f = (m_high * 2^300 + x)^e - c
mm = f.small_roots(X = 2^300, beta = 0.4, epsilon = 0.01)[0] + m_high * 2^300
assert mm == m