import gmpy2

def CRT(n1,n2,n3,c1,c2,c3):
    N1 = n2 * n3
    N2 = n3 * n1
    N3 = n1 * n2
    m1 = gmpy2.invert(N1,n1)
    m2 = gmpy2.invert(N2,n2)
    m3 = gmpy2.invert(N3,n3)
    res = (c1 * m1 * N1 + c2 * m2 * N2 + c3 * m3 * N3) % (n1 * n2 * n3) # m^e % N 的结果
    print(res)
    return res



res = CRT(5,11,17,2,3,5)
print(res)
