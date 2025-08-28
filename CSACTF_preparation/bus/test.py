import gmpy2
import asn1tools
from Crypto.Util.number import long_to_bytes

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