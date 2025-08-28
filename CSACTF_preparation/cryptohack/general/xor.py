from pwn import *

num = 13
st = 'label'
cipher = ''

for i in st:
    cipher += chr(num ^ ord(i))


print("crypto{" + cipher + "}")