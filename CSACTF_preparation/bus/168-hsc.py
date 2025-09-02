from sage.all import *
import gmpy2
'''
MT = matrix(Zmod(256), [[?, ?, ?], [?, ?, ?], [?, ?, ?]]) # ? means unknown number
assert MT.is_invertible()
flag = "AAA{?????????????????????????}" # ? means unknown printable char, len == 30
FT = matrix(Zmod(256), 3, 10)
for i in range(3):
	for j in range(10):
		FT[i, j] = ord(flag[i + j * 3])
RT = MT * FT
result = b''
for i in range(10):
	for j in range(3):
		result += bytes([RT[j, i]])
print(result)

s = b'\xfc\xf2\x1dE\xf7\xd8\xf7\x1e\xed\xccQ\x8b9:z\xb5\xc7\xca\xea\xcd\xb4b\xdd\xcb\xf2\x939\x0b\xec\xf2'

RT=[]
for i in range(30):
    RT.append(s[i])
# [252, 242, 29, 69, 247, 216, 247, 30, 237, 204, 81, 139, 57, 58, 122, 181, 199, 202, 234, 205, 180, 98, 221, 203, 242, 147, 57, 11, 236, 242]
    
MT
a11  a12  a13
a21  a22  a23
a31  a32  a33

 
a1 = gmpy2.invert(65,256) * RT[0] % 256
a2 = gmpy2.invert(65,256) * RT[1] % 256
a3 = gmpy2.invert(65,256) * RT[2] % 256
print(a1,a2,a3) # 252 114(370?) 221

for a11 in range(253):
    for a12 in range(253-1):
        a13 = 252-a11-a12
'''

'''
encoded = b'\xfc\xf2\x1dE\xf7\xd8\xf7\x1e\xed\xccQ\x8b9:z\xb5\xc7\xca\xea\xcd\xb4b\xdd\xcb\xf2\x939\x0b\xec\xf2'
encoded_iter = iter(encoded)

ans = [[0 for i in range(10)] for j in range(3)]
i = 0

for element in encoded_iter:
    ans[i % 3][i // 3] = element
    i += 1

for i in range(3):
    print(ans[i])
'''


# 定义模数
m = 256
encoded = b'\xfc\xf2\x1dE\xf7\xd8\xf7\x1e\xed\xccQ\x8b9:z\xb5\xc7\xca\xea\xcd\xb4b\xdd\xcb\xf2\x939\x0b\xec\xf2'
encoded_iter = iter(encoded)
# 密文矩阵 (3x10)
RT = matrix(Zmod(m), [
    [252,  69, 247, 204,  57, 181, 234,  98, 242,  11],
    [242, 247,  30,  81,  58, 199, 205, 221, 147, 236],
    [ 29, 216, 237, 139, 122, 202, 180, 203,  57, 242]
])

def check(matrix):
    for i in range(3):
        for j in range(10):
            if matrix[i,j] < 32 or matrix[i,j] > 126:
                return False
    return True

line1 = []
line2 = []
line3 = []

a1 = RT[0,0]
a2 = RT[1,0]
a3 = RT[2,0]
b1 = RT[0,1]
b2 = RT[1,1]
b3 = RT[2,1]
c1 = RT[0,9]
c2 = RT[1,9]
c3 = RT[2,9]

for i in range(256):
    for j in range(256):
        for k in range(256):
            if (a1 * i + a2 * j + a3 * k) % 256 == 65:
                if (32 <= (247 * i + 30 * j + 237 * k) % 256 <= 126 and 32 <= (204 * i+81 * j+139 * k) % 256 <= 126 and 32 <= (57 * i + 58 * j + 122 * k) % 256 <= 126):
                    if (b1 * i + b2 * j + b3 * k) % 256 == 123:
                        line1.append([i, j, k])
                    elif (c1 * i + c2 * j + c3 * k) % 256 == 125:
                        line3.append([i, j, k])
                    else:
                        line2.append([i, j, k])
print(line1)

total = 0
MTN = matrix(Zmod(256), [[0,0,0],[0,0,0],[0,0,0]])
for i in line1:
    for j in line2:
        for k in line3:
            for l in range(3):
                MTN[0,l] = i[l]
                MTN[1,l] = j[l]
                MTN[2,l] = k[l]
            if MTN.is_invertible():
                FT_cal = MTN * RT
                if check(FT_cal):
                    total += 1
                    print("Case "+str(total)+":")
                    print(FT_cal)
                    print("\n")