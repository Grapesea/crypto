# Eulid algorithm to find gcd

a = 26513
b = 32321

def gcd(a,b):
    if (a % b == 0 or b % a == 0):
        return min(a,b)
    else:
        return gcd(b, a % b)
    
def extended_gcd(a,b):
    if b == 0:
        return a, 1, 0
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return g, x, y
    
print(gcd(a,b))
print(extended_gcd(a,b))