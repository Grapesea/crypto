from gmpy2 import gcd, invert
f = open("ci.txt", "r").read()
indexes = []
st = 0
while True:
    st = f.find(" {gY ", st)
    if st == -1:
        break
    indexes.append(st)
    st += 1
print("Found at indexes:", indexes)
keylen = indexes[1] - indexes[0]
for x in range(1,len(indexes)-1):
    keylen = gcd(indexes[x+1] - indexes[x], keylen)
print(keylen)
textlist=' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\t\n'
now = "{gY"
past = "the"
now1 = 'O'
past1 ='A'
now2 = ';9'
past2 = 'en'
now3 = 'a).aQ'
past3 = 'nment'

now4 = '8'
past4 = 'h'

now5 = 'XOM'
past5 = 'tor'

now6 = 'yE'
past6 = 'gh'

now7 = '85SY8'
now8 = 'o:|k\'y'
past7 = 'eenth' 
past8 = 'centur'
now9 = 'Q'
past9 = 'a'

key = [1 for i in range(29)]
for i in range(3):
    nowp = textlist.index(now[i])
    pastp = textlist.index(past[i])
    key[3+i] = nowp * invert(pastp, 97) % 97

nowp = textlist.index(now1)
pastp = textlist.index(past1)
key[2] = nowp * invert(pastp, 97) % 97

nowp = textlist.index(now4)
pastp = textlist.index(past4)
key[28] = nowp * invert(pastp, 97) % 97

nowp = textlist.index(now9)
pastp = textlist.index(past9)
key[21] = nowp * invert(pastp, 97) % 97

for i in range(2):
    nowp = textlist.index(now2[i])
    pastp = textlist.index(past2[i])
    key[i] = nowp * invert(pastp, 97) % 97

for i in range(5):
    nowp = textlist.index(now3[i])
    pastp = textlist.index(past3[i])
    key[i+6] = nowp * invert(pastp, 97) % 97

for i in range(3):
    nowp = textlist.index(now5[i])
    pastp = textlist.index(past5[i])
    key[i+11] = nowp * invert(pastp, 97) % 97

for i in range(2):
    nowp = textlist.index(now6[i])
    pastp = textlist.index(past6[i])
    key[i+14] = nowp * invert(pastp, 97) % 97

for i in range(5):
    nowp = textlist.index(now7[i])
    pastp = textlist.index(past7[i])
    key[i+16] = nowp * invert(pastp, 97) % 97



for i in range(6):
    nowp = textlist.index(now8[i])
    pastp = textlist.index(past8[i])
    key[i+22] = nowp * invert(pastp, 97) % 97

print(key)

def decrypt(s,key):
    out = ''
    for i in range(len(s)):
        preindex = invert(key[i % len(key)], 97) * textlist.index(s[i]) % 97
        out += textlist[preindex]
    return out
decrypted_text = decrypt(f, key)
for i in range(len(decrypted_text)//29):
    print(decrypted_text[i*29:i*29+28])

open('de.txt', 'w').write(decrypted_text)