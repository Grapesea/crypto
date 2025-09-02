import gmpy2
import asn1tools
from Crypto.Util.number import long_to_bytes
'''
n = 0x00c2636ae5c3d8e43ffb97ab09028f1aac6c0bf6cd3d70ebca281bffe97fbe30dd
e = 65537
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239
cipher = 0x1c194cd4f48d77b2e14cace43869bea17615ab23da0ef63b7bf56116ad3ac93b
c = int(cipher)
phi = (p-1)*(q-1)
d = gmpy2.invert(e,phi)
m = pow(c,d,n)
print(long_to_bytes(m))
'''
n = 0x81a8a5d31d394cf22be1279821b393cf40fc50bfee4720c5a37d4adcca081733d4386a528d156db3c8e9a464c1d16057e656af4fd9b23ec162b2732758646f62c7349ddf384d415b177e7e4f9177d381da8ba389ea19c86baad6d4e18095cdb8221117260d7bb790bc8b5a8902022dc4f4614be72709d382be0f185ed474805b
# print(int(n))

e = 65537
dp = 0x46b50ee343445e826f0405f22a61902efeed47dd29e69b351ccb0e7d6377981c29dc6277a98934375f50de7309299fe92772110f855ee0d3af948185ee473c17
# assert dp == d%(p-1)
# assert c == pow(m, e, n)
# print(e*dp-1)

li = [2,3,89,389,563,1429,169968591513043511,3667981971308739542102537,15755982260070350867116411,147841219862878791677613767939084109134052890161976374292828659446291852336876599]

for k in range(1024):
    p = 1
    cnt = 0
    k_ = k
    while (k_ != 0):
        if (k_ % 2 == 1):
            p *= li[cnt]    
        cnt += 1
        k_ = k_ // 2
    if (n % (p+1) == 0):
        print(p+1)
        print(n//(p+1))
