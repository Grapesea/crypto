#from sage.all import *

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
b'\xfc\xf2\x1dE\xf7\xd8\xf7\x1e\xed\xccQ\x8b9:z\xb5\xc7\xca\xea\xcd\xb4b\xdd\xcb\xf2\x939\x0b\xec\xf2'
'''

'''
n = 3
A = random_matrix(ZZ, n, n)

while (A.determinant() == 0):
    A = random_matrix(ZZ, n, n)

A_inv = A.inverse()

print(A_inv)
'''

s = b'\xfc\xf2\x1dE\xf7\xd8\xf7\x1e\xed\xccQ\x8b9:z\xb5\xc7\xca\xea\xcd\xb4b\xdd\xcb\xf2\x939\x0b\xec\xf2'

# first__bytes = s[:4]
# byte_values = [b for b in first__bytes]

RT=[252, 242, 29, 69]
for i in range(25):
    RT.append(0)
RT.append(242) # 这个是RT的一部分

print(ord('{'))


