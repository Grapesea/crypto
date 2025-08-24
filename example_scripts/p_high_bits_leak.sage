from Crypto.Util.number import *

p, q = getPrime(512), getPrime(512)
n = p * q
p_high = p >> 100
P.<x> = PolynomialRing(Zmod(n))
f = x + p_high*2^100
pp = ZZ(f.small_roots(X = 2^100, beta = 0.4)[0] + p_high*2^100)
assert pp == p