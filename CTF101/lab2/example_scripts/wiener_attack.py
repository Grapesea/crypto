'''
下面的代码是我自己之前手搓的，有兴趣的同学可以自己实现一遍，或者使用现成的库：https://github.com/pablocelayes/rsa-wiener-attack
'''

from Crypto.Util.number import *
from gmpy2 import *
from sympy import nextprime

def ContinuousFraction(x, y):
    res = []
    while y != 0:
        res.append(x // y)
        x, y = y, x % y
    return res


def evaluate_fraction(List):
    List.reverse()
    denominator = 0
    numerator = 1
    for i in List:
        denominator, numerator = numerator, i * numerator + denominator
    return denominator, numerator

def Enumerate(x, y):
    CF = ContinuousFraction(x,y)
    denominators = []
    numerators = []
    for i in range(len(CF)):
        denominator, numerator = evaluate_fraction(CF)
        CF.reverse()
        denominators.append(denominator)
        numerators.append(numerator)
        CF = CF[:-1]
    return denominators, numerators

def solve(a, b, c):
    delta = b*b - 4*a*c
    if delta < 0:
        return (0,0)
    delta = isqrt(delta)
    if (-b + delta) % (2 * a) != 0 and (-b - delta) % (2 * a) != 0:
        return (0, 0)
    return ((-b + delta) // (2 * a),(-b - delta) // (2 * a))

def WienerAttack(n,e):
    el, nl = Enumerate(n,e)
    for i in range(len(el)):
        if el[i] == 0: continue
        if (nl[i] * e - 1) % el[i] !=0 : continue
        phi = (e * nl[i] - 1) // el[i]
        p, q = solve(1, phi-n-1, n)
        if p*q == n:
            print("Find it!")
            return (p,q)
    print("Failed")
    return (0,0)

m = bytes_to_long(b'this_is_a_sample_flag')
p = getPrime(512)
q = getPrime(512)
n = p * q
d = nextprime(int(n**0.25/3))
phi = (p-1)*(q-1)
e = invert(d, phi)
c = pow(m, e, n)

p, q=WienerAttack(n, e)
phi = (p-1)*(q-1)
d = invert(e, phi)
print(long_to_bytes(pow(c, d, n)))
