# https://zjusec.com/challenges/30
from base64 import b64encode, b64decode
'''
key= ? #message lost
assert(len(key)<14)
for k in key:
  assert(0<=k<256)
  
def xor(text,key):
  new_text=list(text)
  for i in range(len(text)):
    new_text[i]=key[i%len(key)]^text[i]
  return bytes(new_text)

plain= ? #message lost
assert('AAA' in plain)

assert(cipher.encode()==b64encode(xor(b64encode(xor(plain.encode(),key)),key)))'''
'''
cipher = 'Dq4l/8bPnCsynznU2relLC+oGsq+xIBhBrgF+ZKHgjkM6yrxxsOyDzLuB4mDp6kHKZYkyqWf+HIGqDv1xITzJhutD/nGkpwoMp89y82doQcshjjKubX9cwbpAdudk7gGA+lY7I+8+R4umAOKho65CDOsO82lnJx/BrgJyZjA/ycOvg/qwMOYEzCkPdWEgeQMcOUJyLmMjCURkUPbnZeGPA+6WIU='

def xor(text, key):
    new_text=list(text)
    for i in range(len(text)):
        new_text[i]=key[i%len(key)]^text[i]
    return bytes(new_text)

key = []
for i in range(3):
    plain = 'A'
    for j in range(256):
        test_key = chr(j)
        if cipher[i].encode() == b64encode(xor(b64encode(xor(plain.encode(),test_key)),test_key)):
            key += test_key

print(key)

from base64 import b64decode, b64encode

cipher = 'Dq4l/8bPnCsynznU2relLC+oGsq+xIBhBrgF+ZKHgjkM6yrxxsOyDzLuB4mDp6kHKZYkyqWf+HIGqDv1xITzJhutD/nGkpwoMp89y82doQcshjjKubX9cwbpAdudk7gGA+lY7I+8+R4umAOKho65CDOsO82lnJx/BrgJyZjA/ycOvg/qwMOYEzCkPdWEgeQMcOUJyLmMjCURkUPbnZeGPA+6WIU='

def xor(text, key):
    return bytes(key[i % len(key)] ^ text[i] for i in range(len(text)))

def decrypt(cipher_str, key):
    try:
        step3 = b64decode(cipher_str)
        step2 = xor(step3, key)
        step1 = b64decode(step2)
        return xor(step1, key).decode('utf-8', errors='ignore')
    except: 
        return ""

key = []
for i in range(3):
    for j in range(256):
        test_key = key + [j]  # 整数列表
        if 'AAA' in decrypt(cipher, test_key):
            key.append(j)
            break

print(key)'''

from base64 import b64decode, b64encode

cipher = 'Dq4l/8bPnCsynznU2relLC+oGsq+xIBhBrgF+ZKHgjkM6yrxxsOyDzLuB4mDp6kHKZYkyqWf+HIGqDv1xITzJhutD/nGkpwoMp89y82doQcshjjKubX9cwbpAdudk7gGA+lY7I+8+R4umAOKho65CDOsO82lnJx/BrgJyZjA/ycOvg/qwMOYEzCkPdWEgeQMcOUJyLmMjCURkUPbnZeGPA+6WIU='

def xor(text, key):
    new_text = list(text)
    for i in range(len(text)):
        new_text[i] = key[i % len(key)] ^ text[i]
    return bytes(new_text)

key = []
for ran in range(1, 14):  # key长度小于14
    for i in range(ran):
        for j in range(256):
            test_key = key + [j]
            try:
                step1 = b64decode(cipher.encode())  
                step2 = xor(step1, test_key)        
                step3 = b64decode(step2)            
                plain = xor(step3, test_key).decode() 
                if 'AAA' in plain:
                    key.append(j)
                    print(f"找到第{i+1}位: {j}")
                    break
            except:
                continue
        if len(key) != i + 1:
            break

print(f"完整key: {key}")