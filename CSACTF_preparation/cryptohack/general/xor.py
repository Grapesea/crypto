from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

num = 13
st = 'crypto{'
cipher = 0x0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104

# print()

x = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
# print(long_to_bytes(x))

a1 = int(0xa6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313)
a2 = int(0x37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e)
a3 = int(0xc1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1)
a4 = int(0x04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf)

# KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
# KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
# KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
# FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf

flag = a4 ^ a3 ^ a1
# print(long_to_bytes(flag))

def singlebyte_XOR(input_bytes,key):
    flag = b''
    for a in input_bytes:
        flag += bytes([a ^ key])
    return flag.decode('utf-8')

data = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
decoded = bytes.fromhex(data)

for k in range(256):
    outcome = singlebyte_XOR(decoded,k)
    if 'crypto' in outcome:
        print(outcome)
        break