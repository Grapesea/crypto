# Crypto Lab 2：公钥密码学 Report

<center><b>DDL:8.5 23:59</b></center>

> 实验需要提交实验报告。每道做出来的题均需要写在实验报告中，否则无法给分。**实验报告需要写出每道题的思路并贴上攻击脚本（payload）**。对于没法完整做出的题，也可以叙述自己的思路和解题过程，会酌情给分。
>
> 本次crypto lab涉及的内容大部分是课上讲过的，甚至很多可以通过修改示例程序求解。如果对python和sagemath不够熟悉的话，建议多用搜索引擎，合理利用AI大模型，并多向助教提问
>
> 本次有一道题目为校巴上的三选一，有一道题目部署在[ZJUCTF](https://ctf.zjusec.com/games/5)平台上，另外还有三道[CryptoHack](https://cryptohack.org/challenges/)上比较简单的入门题，可以在上面提交flag验证是否正确
>

## RSA部分（70'） （√）

### RSA (40') （√）

> 下面是校巴上的题目三选一（40分）： 

我选的是[EndlessRSA1](https://zjusec.com/challenges/82) .

首先通过入门关：

```python
''' 第一次交互的内容：
sha256(XXXX + 'ikKO3b').hexdigest() = 75e803bd1d4b6fe22bc345d5625edcf98a717bb496988b8f5f964764c1be98f
Give me XXXX (4 bytes, only contain letters or digits): 
'''
context.log_level = "debug"
conn = remote("10.214.160.13", 12501)
data = conn.recvuntil(b'Give me XXXX (4 bytes, only contain letters or digits):')
server_message = data.decode()
print(server_message)

def string1(server_message):
    pattern = r"sha256\(XXXX\s*\+\s*'([0-9a-zA-Z]+)'\)\.hexdigest\(\)\s*==\s*([0-9a-f]+)"
    match = re.search(pattern, server_message, re.IGNORECASE)

    if match:
        r = match.group(1)
        s = match.group(2)
        return r, s
    return None, None

r,s = string1(server_message)
print("\033[91m这是交互第一轮\033[0m")
print(f'Extracted: r:{r}, s:{s}')

def getxxxx(r,s):
    charset = string.ascii_letters + string.digits
    cnt = 0
    for i in range(1,7):
        for cmb in itertools.product(charset, repeat=i):
            key = ''.join(cmb)
            cnt += 1
            if (cnt % 10000000 == 0):
                print(cnt)
            if hashlib.sha256((key + r).encode()).hexdigest() == s:
                print(f"Key found: {key} after {cnt} attempts")
                return key
    return None

result = getxxxx(r,s)
print(f"找到的XXXX: {result}")
conn.sendline(result)
```

于是收到了一串非常炫酷的东西，之后所有收到的内容都放在了`EndlessRSA1-2nd_Interact.txt`文档中，以下是图片展示：

![2-1-0](photos/2-1-0.png)



其中的核心部分是：

```python
====== Level  0 ======
### n = 0x8455f17fab2a281f13b5dbfde0ae23627506e15810bf475d64bb980f1ac94d996af7bf9e99cf03a2e29df69790197f14ccd99c6899f95065e274a6b0e846a21227a7ec1cfdd715e4140f33a9b50ebb5957cb109cf442afc258970c2cc93207189400749e93d14fa23e49f3c3e9a865a73267753691459b12dc095a62931793b7
### e = 0x10001
### c = 0x23a8933260b5853304df1b70f83ea82111b214ae3f38f50623cc7db1af6000e3af7a4f28a78c098f78481bdb4ff750645572c3b87a599fb4d4b064e7c4f08e1de3277cfe285fcbe49ddf269a48190f96b8ea58bf111e2fdcbccfd55a37f886add8c497760e5d4704c48180e0079c0b4bb498359dce9519d9a985356a09cd15f9
### p = 0xb3820dcdf69fad3244c7c2e87640349cc3b047988adcec2effdbf08a403d9e489ee5f52c443b67f85936e18e3859cb9f935a0abf137a6a75a28c666c1c68ed51
### q = 0xbcba04175202449fc9e78fb88595c94aab19fea2031ce3ca78f10a02e27b07c0ab0c7a97538418341f055be9aaff93a8c703ad985e7a4227224831265c480e87
!!! assert c == pow(m, e, n)
@@@ m = 
```

是个简单的RSA加密关，easy，只需要书写以下代码：

```python
def restore_m(n,e,c,p,q):
    phi_n = (p-1) * (q-1)
    d = gmpy2.invert(e,phi_n)
    m = pow(c,d,n)
    return m

m = restore_m(n,e,c,p,q)
print(f"计算出m: {m}")
conn.sendline(hex(m)[2:])
```

通过后到达：

```bash
====== Level  1 ======
### n = 0x957e8b13c7f51abca84d7a3dec3f70dfeb9fc442765212158539941b9a6fe97b
### e = 0x10001
### c = 0x7f718a1c2704b4f08059b8c9e80bd3a4682c677842ff250e5ee4513c48cace52
!!! assert c == pow(m, e, n)
@@@ m = 
```

这里涉及到了大素数分解，绷不住了用Pollard p-1和Fermat怎么都要跑好久，于是下载了yafu进行分解.

```bash
PS D:\Downloads\yafu> .\yafu-x64.exe "factor(67618197045107935018171254777337861763230777994121505976964443590156950169979)"
```

得到：

```bash
fac: factoring 67618197045107935018171254777337861763230777994121505976964443590156950169979
fac: using pretesting plan: normal
fac: no tune info: using qs/gnfs crossover of 95 digits
div: primes less than 10000
fmt: 1000000 iterations
rho: x^2 + 3, starting 1000 iterations on C77
rho: x^2 + 2, starting 1000 iterations on C77
rho: x^2 + 1, starting 1000 iterations on C77
pm1: starting B1 = 150K, B2 = gmp-ecm default on C77
ecm: 30/30 curves on C77, B1=2K, B2=gmp-ecm default
ecm: 74/74 curves on C77, B1=11K, B2=gmp-ecm default
ecm: 149/149 curves on C77, B1=50K, B2=gmp-ecm default, ETA: 0 sec

starting SIQS on c77: 67618197045107935018171254777337861763230777994121505976964443590156950169979

==== sieving in progress (1 thread):   36224 relations needed ====
====           Press ctrl-c to abort and save state           ====
36128 rels found: 18625 full + 17503 from 185071 partial, (3972.68 rels/sec)

SIQS elapsed time = 52.5015 seconds.
Total factoring time = 60.3994 seconds


***factors found***

P39 = 265484613684666748942228552342347106471
P39 = 254697235017252043734581962613870599949

ans = 1
```

于是：

```python
p = 265484613684666748942228552342347106471
q = 254697235017252043734581962613870599949

phi_n = (p-1) * (q-1)
d = gmpy2.invert(e,phi_n)
m = pow(c,d,n)
print(f"\033[91m计算出m_2: {m}\033[0m")
conn.sendline(hex(m)[2:])

# 这部分的质因数分解是用yafu工具实现的，试了几次发现n的值不变，所以大胆给p,q赋值.
```

啊啊啊啊啊啊原来只要分解一次就行了，真的破大防了.



接下来是：

```bash
====== Level  2 ======
### n = 0x75c14feb68d40564271f8da54a1973dad15d47fe0a7101d5056e84d2fcaf3c17ec62cdd4b1662ab6319b410122fd2e2dd128b535bb61eadc6891ee02f982a8356894033ba24c1b5ea42e5a6166f427970d415c9b1ff635213dea6fb116b386d3d6362f2f00579f6e273320a9ad3b0a9895cdacfadd7c5eacd5e3121ac420f93b
### e1 = 0xa8eb28b3
### e2 = 0xe54d3167
### c1 = 0x10e64617de6b664c88af52bb51a7a57c64ac3427a80b19d02a7fbed022631ba7baaeb10026193525b36ce378781b8f382bb88e08b7e16cca1e6314f4eb94019cf76c9f5f64cf2fd981e42cc459e526bf5263a79f744e26114ff04d3206d570fa7d143ec5d205a16684bac4f0dd16f91c622e6ece8628a45ea56575a303c8f42b
### c2 = 0x6353d6ba409275651e13e2fad14d5f4dce7d57de645197541f79fa3c222ccf6c173186e4df1a9edf33e941f22246842e99676f57ace226b3280621281200de1e893d7cd15b8f33a6239a04133f60a9ca9f3d0a79361ff3a70f91a1802cb26898e6f5b4b4003963a4e9bda36c48e8beef3076a8db50ff3c35ce2fbd043a59e55f
!!! assert c1 == pow(m, e1, n)
!!! assert c2 == pow(m, e2, n)
@@@ m = 
```

属于是吃一堑长一智，直接又跑了次结果，发现$n,e_1,e_2$没变，所以直接赋值.

这道题搜了一下，核心是“共模攻击”问题，需要用到扩展欧几里得算法.

> 扩展欧几里得算法：
>
> egcd是利用递归回溯，在计算gcd的过程中找到符合Bezout等式的$x,y$的过程.
>
> 在辗转相除的过程中，其中一环是$gcd(a,b) = gcd(b,a(\operatorname{mod}b)) (*)$
>
> 现在设已经计算出下一层的解：$bx'+a(\operatorname{mod}b)y' = gcd(b,a(\operatorname{mod}b)) (**)$
>
> 则把(*)带入到(**)中，有：
>
> 

所以书写：

```python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def solve():
    g, x, y = egcd(e1, e2)
    if x < 0:
        x = -x
        c1_inv = gmpy2.invert(c1, n)
        result = pow(c1_inv, x, n)
    else:
        result = pow(c1, x, n)
    if y < 0:
        y = -y
        c2_inv = gmpy2.invert(c2, n)
        result = (result * pow(c2_inv, y, n)) % n
    else:
        result = (result * pow(c2, y, n)) % n
    return result

m = solve()
```

接下来是：

```bash
Received 0x35d bytes:
    b'====== Level  3 ======\n'
    b'### n = 0xce202f8fd1b78c23dfa53314617510cd422e3f4c5aa412400ed44abaf3d4bbdf4230c8f9f73736c32cbcbec0c7780b6b56f7d4bea1678640581cd4aaf2df9ff4175846fc44ddf94e924a188d0b0989ecc462da8c5e88c295e26beeafab201ab6ab299dc0f0106dd1a3cc21d17c757130be6f3f0b5b250932396f34ac3295d057\n'
    b'### e = 0x684b3ab9779f91c23597668e5eb8dd73a3333f9fb7a456583204d255576bef204a1201d276a00cb88d531c3aa993e7304162bf673baebffc39210a1c3faa64712a4e12c1da67eb98817d981bc8bbe9d4cf605903fc039b507e8b77248a88c995741b152c41609d3d86518cba8d9da419dd36e8f8bc07881be87990ea26873b6b\n'
    b'### c = 0x9d749f88d638b0a560d7cd7896f9fb07b10dd0cd5c3771742d3a4388750e1d26353daea617de31f6a98e9a1c06de4df3baa54de3adaf3c238c7405c8d81d5a0efacfff8284584489d1bd5611e0dd5faf850982dfed6adb15f173b279244e8b75e97cb08b3772c78e36a711f98c69558d628e51353ae241f581dd31689a11773b\n'
    b'!!! assert c == pow(m, e, n)\n'
    b'@@@ m = '
```

还是跑了两遍，得到的第二遍：

```bash
[DEBUG] Received 0x35d bytes:
    b'====== Level  3 ======\n'
    b'### n = 0xce202f8fd1b78c23dfa53314617510cd422e3f4c5aa412400ed44abaf3d4bbdf4230c8f9f73736c32cbcbec0c7780b6b56f7d4bea1678640581cd4aaf2df9ff4175846fc44ddf94e924a188d0b0989ecc462da8c5e88c295e26beeafab201ab6ab299dc0f0106dd1a3cc21d17c757130be6f3f0b5b250932396f34ac3295d057\n'
    b'### e = 0x684b3ab9779f91c23597668e5eb8dd73a3333f9fb7a456583204d255576bef204a1201d276a00cb88d531c3aa993e7304162bf673baebffc39210a1c3faa64712a4e12c1da67eb98817d981bc8bbe9d4cf605903fc039b507e8b77248a88c995741b152c41609d3d86518cba8d9da419dd36e8f8bc07881be87990ea26873b6b\n'
    b'### c = 0x5b7948b8177ea6c826a360ce98ec01e4a0de030e6e29537862f5312bb55a9117c2a01dae28040bad3677e3871ba00abaa67d30a64e38102ab33c47c16fea6f420c7b565ce48fa57e09eb7f62fc95adaad036f33acaaf010dd83592dfc93d3eae1ba6b8ae9c1723ded27132da37a5681170e0286a7a9c3418c6dcc49130926145\n'
    b'!!! assert c == pow(m, e, n)\n'
    b'@@@ m = '
```

也就是说，难度相较于Level 1又升级了，虽然$n,e$仍然是已知的固定数，但数量级大了很多以至于难以分解（都是1024bits）这道题的方法跟下面的1.2.3一致，均使用了连分数展开，所以不赘述.

代码：

```python
def continued_fractions(n, d): #计算n/d的连分数展开
    fractions = []
    while d:
        q = n // d
        fractions.append(q)
        n, d = d, n - q * d
    return fractions

def convergents(cf):     # 从连分数计算收敛分数
    convergents_list = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    
    for a in cf:
        h_next = a * h_curr + h_prev
        k_next = a * k_curr + k_prev
        convergents_list.append((h_next, k_next))
        h_prev, h_curr = h_curr, h_next
        k_prev, k_curr = k_curr, k_next
    
    return convergents_list

def wiener_attack(e, N):
    cf = continued_fractions(e, N)
    convergents_list = convergents(cf)
    
    for k, d in convergents_list:
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k == 0:
            phi_candidate = (e * d - 1) // k
            
            # 尝试分解N
            # N = p*q, φ(N) = (p-1)*(q-1) = N - p - q + 1
            # 所以 p + q = N - φ(N) + 1
            s = N - phi_candidate + 1
            discriminant = s * s - 4 * N
            
            if discriminant >= 0:
                sqrt_discriminant = isqrt(discriminant)
                if sqrt_discriminant * sqrt_discriminant == discriminant:
                    p = (s + sqrt_discriminant) // 2
                    q = (s - sqrt_discriminant) // 2
                    
                    if p * q == N and p > 1 and q > 1:
                        return d, p, q
    
    return None, None, None

def small_d_attack(N, e, c):    # main
    print("Wiener攻击开始")
    d, p, q = wiener_attack(e, N)
    if d is not None:
        print(f"d = {hex(d)}")
        print(f"p = {hex(p)}")
        print(f"q = {hex(q)}")
        phi = (p - 1) * (q - 1)
        if (e * d) % phi == 1:
            m = pow(c, d, N)
            return m
    return None

N = # 略
e = # 略
c = # 略
m = small_d_attack(N, e, c)
```

到了Level 4：

```bash
b'====== Level  4 ======\n'
    b'### n1 = 0x789d6e456a398c562bff3daf709a9fd3c28b139449266e1bb197ebcc3147ce3dbb633bfa45241211cdd89c364abf1cde1b22f5b50d577161296f5642d5e91348d2838e4099b2e93965d33d19ec4d9155923ed2c0f4515f673f29b3107bb3a0493dddd5785db8b1e6dcd97b8b499f06adf383fbcb5d09a59d4428b11784d3e60f\n'
    b'### n2 = 0x7fafec181ff0e6b6e131f97a6c64a202d2cab2903e805a4ee617f7f3bf69b737331795f4019b61f7f980a2b2b0a910125af48712df7b838bbfae86848164a402f3097aa3ad1259e9456b2987f464106a8d4d1e7617799b38bf090f0dfbc0c409d59e3c3d1dee030623cc12433c716e62d1659c219fccfb7aaab54cc499a2bfb5\n'
    b'### n3 = 0x97355de6d682d41b919de591c3d860f1de351327bd8d6801aea336e65e0b09341d96b916da70fcad15f490dcbff615cdf5f30ce69e4afeec500ba48d155e40935e36923e694d4de3c28230e42aebc800fe6c259d0da06b2d575bc6f4c78204c887376caae3d10fa4bc59a4d6a9a0e82521f04322f0f49336231eff63ca8e69ab\n'
    b'### e = 0x3\n'
    b'### c1 = 0x1868e6eeccd409074989451f19d6b56edc9edf032889fab369db1efb098756896b685ccbe221c583463ccbf3b5c5f28c021908aaa9c946e1fc8ff2a8c6c0b5fcb130de8f03f993d2c84df6dcca8dd2eb02340e2b2f3402996836fe85d87053c777a5ebbedb7b29c7219e12357d8cf1c414c8b80d1458f869984ea011e35b3c07\n'
    b'### c2 = 0x2886ec384eee3d02693ee57d7bcae9c7bca02ed621be2032e0d4e58ee228499fab1f5f707585e22aa11ec8a135704a41e8ecd7da8a5deb82e98bd6e1d3c452fde70ac54d3fba65d9bfd5eeaa2f975986ee5e95243515e5b1b2e104'
[DEBUG] Received 0x1bc bytes:
    b'6088e47b0384ace5ecd70040325f2970c1d44b79ebb188c6439a57e2fd1e48b48124fe3913\n'
    b'### c3 = 0x75ba169eab02758769bf3acb7ae035c06fe67cc123c57f9b48a0a0d2c3e50b30a95b02ebfe4d4086f7cedf033f4f196d14db3bbefbff7781834df62788391044bddf39c92427ff3d00f38dbca56cf0c48a5c08a3ed948f0dbab8001827bfa2f1bd41285aa4fbda48954d8f12b3207432283676d59eeb17313a285ea45c108693\n'
    b'!!! assert c1 == pow(m, e, n1)\n'
    b'!!! assert c2 == pow(m, e, n2)\n'
    b'!!! assert c3 == pow(m, e, n3)\n'
    b'@@@ m = '
```

第二次得到的信息是：

```bash
    b'====== Level  4 ======\n'
    b'### n1 = 0x789d6e456a398c562bff3daf709a9fd3c28b139449266e1bb197ebcc3147ce3dbb633bfa45241211cdd89c364abf1cde1b22f5b50d577161296f5642d5e91348d2838e4099b2e93965d33d19ec4d9155923ed2c0f4515f673f29b3107bb3a0493dddd5785db8b1e6dcd97b8b499f06adf383fbcb5d09a59d4428b11784d3e60f\n'
    b'### n2 = 0x7fafec181ff0e6b6e131f97a6c64a202d2cab2903e805a4ee617f7f3bf69b737331795f4019b61f7f980a2b2b0a910125af48712df7b838bbfae86848164a402f3097aa3ad1259e9456b2987f464106a8d4d1e7617799b38bf090f0dfbc0c409d59e3c3d1dee030623cc12433c716e62d1659c219fccfb7aaab54cc499a2bfb5\n'
    b'### n3 = 0x97355de6d682d41b919de591c3d860f1de351327bd8d6801aea336e65e0b09341d96b916da70fcad15f490dcbff615cdf5f30ce69e4afeec500ba48d155e40935e36923e694d4de3c28230e42aebc800fe6c259d0da06b2d575bc6f4c78204c887376caae3d10fa4bc59a4d6a9a0e82521f04322f0f49336231eff63ca8e69ab\n'
    b'### e = 0x3\n'
    b'### c1 = 0x491dd7198e50bc71b67081341ef2d4deaaef94c01bf5b68140c4df6503ede0da1fb7606106170bbf8b5efc077b7669894c6d63e141b0e3426a4140539dc33d050ea09f3df19132d4632a079cc26dc3aa8b434a5bc133e80d11c9c0cb9f1dbe4e87ed4bd169630ff3a14bff48f50ce47501e70a9bc9703b82750ba6d2127aba60\n'
    b'### c2 = 0xd4efa36dceadd73d004871d705d6ac4de94c4e42bed8bf803c7b355fb8583e42dee8e840c63fe5d07da1f81c3aacca9ab81ee73d266e7ec34cbcfec8f185689968e2d7ff2e46267f6e8365c7e364033eb2c5349f8d3da4a238d32e'
[DEBUG] Received 0x1bb bytes:
    b'ad52c3832e9ba02ac8d38457d29255e6efebbbaaa564a5cbece69cc6619311d1aaa0dc553\n'
    b'### c3 = 0x1bd4e2d74fb2a4ad99aa9b3b88098d39a43a365fdd10deb5e5fcd888a737e115724866c44ce51b4f721b5860400e272c2a0202c0f04bb9c1b88bdfc6c9a94ece253779e214d36f5439c7ac0c5e2c94f0950cedcbaa454b559eb5ce4c1a901409693ffde1ff7db4c4c3374e87b67a5cd31a3fb954e89c1a024e6d7ee5e211352d\n'
    b'!!! assert c1 == pow(m, e, n1)\n'
    b'!!! assert c2 == pow(m, e, n2)\n'
    b'!!! assert c3 == pow(m, e, n3)\n'
    b'@@@ m = '
```

所以$n_1,n_2,n_3,e$都是固定的，需要通过已知的$c_1,c_2,c_3$来还原.

```python
def CRT(n1,n2,n3,e,c1,c2,c3):
    N1 = n2 * n3
    N2 = n3 * n1
    N3 = n1 * n2
    m1 = gmpy2.invert(N1,n1)
    m2 = gmpy2.invert(N2,n2)
    m3 = gmpy2.invert(N3,n3)
    res = (c1 * m1 * N1 + c2 * m2 * N2 + c3 * m3 * N3) % (n1 * n2 * n3) # m^e % N 的结果
    print(res)
    return res

res = CRT(n1,n2,n3,e,c1,c2,c3)

def get_m(n1,n2,n3,e,c1,c2,c3,res):
    res = CRT(n1,n2,n3,e,c1,c2,c3)
    m, is_exact = gmpy2.iroot(res, e)
    print(m)
    if is_exact:
        return m
    return None

m = get_m(n1,n2,n3,e,c1,c2,c3,res)
```

这里面有一个细节需要注意，就是开立方根的函数需要使用`gmpy2.iroot(res, e)`，如果一开始不慎使用了`np.power()`或者`math.pow()`那就会被判死刑（浮点数精度问题）.

---

接下来是Level 5: （已经要吐出来了怎么还没完）

```bash
====== Level  5 ======
### n = 0xcb90358774b8013e083254bfbc34d6d3a254f697c1a9e444f51b43698d9dcd296bb6e9adc64c88b5d386e9ee7056111deae86426482a6c8f7332e876ba05774f77f050282cf5daa6f9801c1a27a53f2c1ae465e9952863bdcf13dde0aa9e81d1eadd3007ae6ec7aa30eba2428abc27b643f92a547b4cc0bebf259c657987d6c1
### npnq = 0xcb90358774b8013e083254bfbc34d6d3a254f697c1a9e444f51b43698d9dcd296bb6e9adc64c88b5d386e9ee7056111deae86426482a6c8f7332e876ba05787b347d4f53846a17d3366827068e934a21d02315488d2c99d384b5556aacb265d7ce17e0dc4774aa9d45915d5ea70cfdcf0d2f48a33d2a12234cdbdb61f776c4ed
### e = 0x10001
### c = 0x3f4f6caaf8a360c3852baf594a33fd48653df9febf6d8022bbaebb0143b721f3eac7810d5fbec654f4e113edac83292616f64745e66dab729e5cd9e3ea5d16d8ede98df3b1a0b1a97a5063a3c6adbda18fa6c668a1cc1ba43cccb39f32260cb5d89de5430ed3d0c7ce37487156bfbf868556644fb599ae011c9e2085c642fbfe
!!! assert npnq == next_prime(p) * next_prime(q)
!!! assert c == pow(m, e, n)
@@@ m =
```

再跑一遍，发现给出了固定的$n$和$n$的近似值($p_{next}*q_{next}$)，以及固定的$e=65537$和变动的$c$，现在考虑一个近似分解的算法，改编自这个链接https://www.freebuf.com/articles/database/290623.html：

```python
def fermat_factorization(n):
    factor_list = []
    a = gmpy2.iroot(n,2)[0]
    while True:
        a += 1
        b2 = a * a - n

        if gmpy2.is_square(b2):
            b2 = gmpy2.mpz(b2)
            b,xflag = gmpy2.iroot(b2,2)
            assert xflag
            factor_list.append([a + b, a - b])
            if len(factor_list) == 2:
                break
    return factor_list

n1 = n * npnq
factor_list = fermat_factorization(n1)
X1,Y1=factor_list[0]
X2,Y2=factor_list[1]
assert X1*Y1==n1
assert X2*Y2==n1
p_next=gmpy2.gcd(X1,X2)
q=X1//p_next
p=gmpy2.gcd(Y1,Y2)
q_next=Y1//p
print('p=',p)
print('q=',q)
print('p_next=',p_next)
print('q_next=',q_next)         

def restore_m(n,e,c,p,q):
    phi_n = (p-1) * (q-1)
    d = gmpy2.invert(e,phi_n)
    m = pow(c,d,n)
    return m

m = restore_m(n,e,c,p,q)
```

得到了：

```bash
====== Level  6 ======
### n = 0x43224f32a5593cc97154f712c34b194d1895afd1f7d5c19d0eabfe7a935cad79e51d60ebb4fd9f88e3a0ec1d04a6a75acb4deadd53e3e49b2081e2e686380b1cdc1780891c73433c02f8a64f011f5df9a5168581a567dff2fec26bf0ac2e89347c4c6ed00ccee07c90acb144bfc3cfebf25e4a764959bcf4ecec8784b953950a527
### e = 0x10001
### c = 0xc5cbb1b390e6228da6197178ce8c88491e9a84866844e1cad45fc70ac56ad4245a6ee24ebd397fbf650b045ba1f6e789d5ae22f51ab658ab75b1437bf89027ec9c45e98b0655e39d2ce73bd3c6ffde987eb8e2ddeed0070ac4079f4190b247f8a0f608092949c2e142381f4497b5d4d8aa65735db0cbf9273b542f43c222f4b0c5
!!! assert c == pow(m, e, n)
!!! assert q == next_prime(2019 * p)
@@@ m = 
```

（此刻我怀疑这题的等级划分会致敬超炮）

再跑一遍，可以看出$n,e$是不变的.

考虑变形的Fermat攻击：

因为$\begin{cases} n = p*q \\ q = 2019*p+\epsilon\end{cases}$

所以设$\begin{cases} a = q \\ b = 2019*p\end{cases}$，有：$|a-b|$较小，且$n = a*b//2019$

所以书写代码：

```python
def fermat_factor(n):
    for i in range(1, 1000000):
        sum , _= gmpy2.iroot(4 * n * 2019 + i**2, 2)
        if _ :
            q = (sum + i) // 2
            p = (sum - i) // 4038
            if gmpy2.is_prime(p) and gmpy2.is_prime(q):
                return p, q 
    return None, None

def restore_m(n,e,c,p,q):
    phi_n = (p-1) * (q-1)
    d = gmpy2.invert(e,phi_n)
    m = pow(c,d,n)
    return m

p,q = fermat_factor(n)
print(f"p = {p}")
print(f"q = {q}")
m = restore_m(n,e,c,p,q)
```

其实非常简单但是浪费了太多时间在无效的工作上。

结束了，感觉半条命都搭在里面了。

```bash
[DEBUG] Received 0x4d bytes:
    b'Good!\n'
    b'Well done! Here is the flag: AAA{3ndl3$$_rs4_end1e55_expl01t|7aedfd0f}\n'
```

flag是：`AAA{3ndl3$$_rs4_end1e55_expl01t|7aedfd0f}`

结算画面：

<img src="photos/2-1-1.png" alt="2-1-1" style="zoom: 33%;" />



### CryptoHack (10'$\times$3) （√）

> 下面是CryptoHack上的入门题（均为Public Exponent下的题目）：
>
> [Crossed Wires](https://cryptohack.org/challenges/rsa/)（10分）  
>
> [Everything is Still Big](https://cryptohack.org/challenges/rsa/)（10分） 
>
> [Endless Emails](https://cryptohack.org/challenges/rsa/)（10分）

#### Starter （√）

先根据https://cryptohack.org/challenges/rsa/的指导，按部就班学习一下RSA加密算法的过程：

（个人是先学DSA的，感觉加密方法上RSA更简便一点）

**约定记号：$x=y (\operatorname{mod} N)$表明$x$的满足情况之下最小且唯一性；$x\equiv y (\operatorname{mod} N)$表明$x$只要是使得等式成立的任意值即可.**

首先引入模幂（Modular Exponentiation）的概念：

这是一次取幂再取模操作之后的余数，Python中记作`pow(base, exponent, modulus)`，即$remainder = base^{exponent} (\operatorname{mod}modulus)$

这个操作的正逆向难度不同，即从base, exponent, modulus推出remainder易，但知道了remainder在内的任意三个信息则较难推出剩余信息。

模幂（Modular Exponentiation）和大素数分解（prime factorisation）叠加在一起就能制造出**陷门**（Trap Door, a function that is easy to compute in one direction, but hard to do in reverse unless you have the right information）

<br/>

公钥$(e,N)$的生成：

我们考虑$N = p \times q$作为modulus，其中$p,q$都是素数；$e$是幂，所以公钥对就是$(N,e)$.

常见的$e$值是65537，也就是`0x10001`.

现在我们输入一条待加密信息$m$，用公钥经过模幂计算就可以得到加密文本.

```python
p = 17
q = 23
e = 65537
m = 12
cipher = pow(m, e, p*q)
print(cipher)
```

私钥$(d,N)$（Private Key）:在数值上是满足$d \equiv e^{-1} (\operatorname{mod}\phi(N))$这一方程的**任一正整数解**.

<br/>

拥有了加密后的信息$c$，所有公钥和私钥信息，想要还原$message$，应该怎么做呢？

首先注意到$e \times d \equiv 1 (\operatorname{mod} \phi (N))$，于是$\exists k \in Z, e \times d = 1 + k\phi(N)$

由于$c = m^e (\operatorname{mod} \phi(N))$，所以$c^d \equiv (m^e)^d \equiv m^{ed} \equiv m^{1+k\phi(N)} \equiv m (\operatorname{mod} N)$，

其中后半部分是由欧拉定理得到的：$(m,N) = 1 \Longrightarrow m^{\phi(N)} \equiv 1(\operatorname{mod}N) \Longrightarrow m^{k\phi(N)} \equiv 1(\operatorname{mod}N)$ 

于是$m = c^d(\operatorname{mod} N)$，这就是我们希望的答案.

<br/>

现在我们想要给别人传送信息$m$，又不希望被非目标人员解开.

我们引入Hash函数$H(m)$（常用的有SHA256, MD5 etc.）

首先用朋友的公钥$(N_0,e_0)$加密出$c$：$c = m^{e_0} (\operatorname{mod} N_0)$

然后“签名”：对$H(m)$使用自己的私钥$(N_1,d_1)$加密出新信息$S$：$S = H(m)^{d_1} (\operatorname{mod} N_1)$

此时对方如果想要解密，可以：$m = c^{d_0} (\operatorname{mod} N_0)$

最后验证：

使用自己的公钥$(N_1,e_1)$解密：如果$H'(m) = S^{e_1} (\operatorname{mod} N_1)$与$H(m)$相等，则验证通过.

Starter关通过结算：

<img src="photos/2-2-0.png" alt="2-2-0" style="zoom: 33%;" />

#### Crossed Wires （√）

首先阅读源代码：

```python
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long, inverse
import math
from gmpy2 import next_prime

FLAG = b"crypto{????????????????????????????????????????????????}"

p = getPrime(1024)   # 随机获得一个1024位的质数
q = getPrime(1024)
N = p*q
phi = (p-1)*(q-1)
e = 0x10001               # 熟悉的65537
d = inverse(e, phi)

my_key = (N, d)

friends = 5
friend_keys = [(N, getPrime(17)) for _ in range(friends)]

cipher = bytes_to_long(FLAG) 

for key in friend_keys:
    cipher = pow(cipher, key[1], key[0])   # 迭代式的加密方法

print(f"My private key: {my_key}")
print(f"My Friend's public keys: {friend_keys}")
print(f"Encrypted flag: {cipher}")
```

可以知道这个是使用了5个$d$轮流加密获得了最终的值.（一开始理解成我私钥中的的$d$也加密了一次，导致一直报错）

于是书写代码：路径是`1-Crossed_wires\solution.py`

```python
import math
import gmpy2
from Crypto.Util.number import long_to_bytes

N = # 略
d_pri = # 略
e1 = 65537

e0_list = [106979, 108533, 69557, 97117, 103231]

cipher = # 略

'''
friend_keys = [(N, getPrime(17)) for _ in range(friends)]
cipher = bytes_to_long(FLAG)
for key in friend_keys:
    cipher = pow(cipher, key[1], key[0])
'''
k_phi = e1 * d_pri - 1
phi = None
for k in range(1, 100):
    if k_phi % k == 0:
        potential_phi = k_phi // k
        if pow(e1, -1, potential_phi) == d_pri:
            phi = potential_phi
            print(f"Found phi with k={k}: {phi}")
            break
cur = cipher

for i in range(4,-1,-1):
    d_inv = gmpy2.invert(e0_list[i], phi)
    cur = pow(cur, d_inv, N)
    
flag = long_to_bytes(cur)
if flag.decode('utf-8'):
    print("Success!")
    print(flag)
else:
    print("Failed")
```

运行之后得到flag为：

`crypto{3ncrypt_y0ur_s3cr3t_w1th_y0ur_fr1end5_publ1c_k3y}`



#### Everything is Still Big （√?）

1.2.3和1.2.4似乎是论文题，所以先阅读为敬.

从P4的Low Private Exponent看起：

> Wiener Theorem：
>
> 如果$N = p*q (q < p < 2p), d < \dfrac{1}{3}N^{\frac{1}{4}}$，则在已知$(N,e)$的情况下，$d$是可以恢复的.
>

好怪啊，为什么1.2.3中的源代码里面，居然是：

```python
        if (3*d)**4 > N and gcd(d,phi) == 1:
            e = inverse(d, phi)
```

不管怎么样先写出来：（使用了Claude辅助书写）

```python
def continued_fractions(n, d): #计算n/d的连分数展开
    fractions = []
    while d:
        q = n // d
        fractions.append(q)
        n, d = d, n - q * d
    return fractions

def convergents(cf):     # 从连分数计算收敛分数
    convergents_list = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    
    for a in cf:
        h_next = a * h_curr + h_prev
        k_next = a * k_curr + k_prev
        convergents_list.append((h_next, k_next))
        h_prev, h_curr = h_curr, h_next
        k_prev, k_curr = k_curr, k_next
    
    return convergents_list

def wiener_attack(e, N):
    cf = continued_fractions(e, N)
    convergents_list = convergents(cf)
    
    for k, d in convergents_list:
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k == 0:
            phi_candidate = (e * d - 1) // k
            
            # 尝试分解N
            # N = p*q, φ(N) = (p-1)*(q-1) = N - p - q + 1
            # 所以 p + q = N - φ(N) + 1
            s = N - phi_candidate + 1
            discriminant = s * s - 4 * N
            
            if discriminant >= 0:
                sqrt_discriminant = isqrt(discriminant)
                if sqrt_discriminant * sqrt_discriminant == discriminant:
                    p = (s + sqrt_discriminant) // 2
                    q = (s - sqrt_discriminant) // 2
                    
                    if p * q == N and p > 1 and q > 1:
                        return d, p, q
    
    return None, None, None

def small_d_attack(N, e, c):    # main
    print("Wiener攻击开始")
    d, p, q = wiener_attack(e, N)
    if d is not None:
        print(f"d = {hex(d)}")
        print(f"p = {hex(p)}")
        print(f"q = {hex(q)}")
        phi = (p - 1) * (q - 1)
        if (e * d) % phi == 1:
            m = pow(c, d, N)
            return m
    return None

N = # 略
e = # 略
c = # 略
m = small_d_attack(N, e, c)
    
if m:
    flag = Crypto.Util.number.long_to_bytes(m)
    print(f"m = {hex(m)}")
    print(f"flag = {flag}")
```

最后结果是：`crypto{bon3h5_4tt4ck_i5_sr0ng3r_th4n_w13n3r5}`

---

看了一下官方题解[CryptoHack – Everything is Still Big Solutions](https://cryptohack.org/challenges/big2/solutions/)也有点迷的，想不明白Wiener攻击甚至可以的原因.



官方题解：

> The condition $d \geq \dfrac13 N^{1/4}$ in the parameter generation prevents the Wiener attack, but it is still possible that d is still very low and can be recovered.
>
> Contrary to what is said in the flag content, Boneh's attack is not necessary for this challenge. Indeed, a simple reduction of a 2 dimensional lattice can be applied to find the private exponent d. The principle is explained in pages 34 and 35 of Public-Key Cryptanalysis by Nguyen.
>
> The general idea is the following. We know there exists an integer k such that $ed=1+kφ(N)$
>
> The public exponent is chosen to be almost the same size as φ(N) so k is expected to be the same size of d. So we have $ed−kN=1+k(1−(p+q))=O(d\sqrt{N})$.
>
> Now consider the lattice generated by the rows of the matrix $M = \begin{bmatrix} e & \sqrt{N} \\ N & 0\end{bmatrix}$.
>
> Then the vector $(ed−kn,d\sqrt{N})$ is a short vector of the lattice, under the assumption that d is very low. Applying a lattice reduction (see the CryptoHack challenge [Gaussian Reduction](https://cryptohack.org/challenges/maths/) to implement it yourself, or use LLL), this vector can be found, and d can be extracted from its second coordinate.
>
> Here the code working for SageMath version 9.1:
>
> ```python
> N = # 略
> e = # 略
> c = # 略
> 
> s = floor(sqrt(N))
> M = Matrix([[e, s], [N, 0]])
> Mred = M.LLL()
> D = [abs(Mred[i, 1]) // s for i in [0,1]]
> 
> for d in D:
>     t = randint(2, N - 2)
>     tt = pow(t, e, N)
>     if tt^d != t:
>         continue
>     flag = int(pow(c, d, N))
>     flag = flag.to_bytes((flag.bit_length() + 7)//8, 'big')
>     print(f'FLAG: {flag.decode()}')
> ```

---

#### Endless Emails（√）

这里给出了一大堆$(n,e,c)$，而且$e$非常小，仅为3. 但是跟上面的CRT攻击不太一样，这里的所有$n$互素，很难直接攻击出结果来.

理解错误题目的意思了，原来题意是，7组里面只有3组是对的，而我却傻乎乎地尝试了好久还以为算法不够先进，哎。

书写代码遍历：

```python
import hashlib
import itertools
import string
import re
import gmpy2
import math
import requests 
from pwn import *
import numpy as np
from math import isqrt, gcd
from fractions import Fraction
import Crypto.Util.number

# 太长了省略n1-n7;c1-c7，参见源代码

n_list = [n1,n2,n3,n4,n5,n6,n7]
c_list = [c1,c2,c3,c4,c5,c6,c7]

def CRT(n_list,c_list,i,j,k):
    N_list = [n_list[k]*n_list[j], n_list[i]*n_list[k], n_list[j]*n_list[i]]
    m_list = []
    m_list.append(gmpy2.invert(N_list[0],n_list[i]))
    m_list.append(gmpy2.invert(N_list[1],n_list[j]))
    m_list.append(gmpy2.invert(N_list[2],n_list[k]))

    N = n_list[i]*n_list[j]*n_list[k]

    res = c_list[i] * m_list[0] * N_list[0] + c_list[j] * m_list[1] * N_list[1] + c_list[k] * m_list[2] * N_list[2]
    res = res % N
    print("\033[91m这是res:\033[0m")
    return res

def get_m(e, res):
    m, is_exact = gmpy2.iroot(res, e)
    if is_exact:
        print("\033[91m这是m:\033[0m")
        print(m)
        return m
    return None

e = 3
cnt = 0

for i in range(5):
    for j in range(i+1,6):
        for k in range(j+1,7):
            cnt += 1
            print(f"这是{cnt}次: ")
            res = CRT(n_list,c_list,i,j,k)
            m = get_m(e, res)
            if m:
                print(f"找到m: {m}")
                flag = Crypto.Util.number.long_to_bytes(int(m))
                print("\033[91m这是flag:\033[0m")
                print(f"flag = {flag}")
                break
```

所以输出的含有flag的文段是：

```bash
flag = b'yes\n\n---\n\nJohan Hastad\nProfessor in Computer Science in the Theoretical Computer Science\nGroup at the School of Computer Science and Communication at KTH Royal Institute of Technology in Stockholm, Sweden.\n\ncrypto{1f_y0u_d0nt_p4d_y0u_4r3_Vuln3rabl3}'
```

三个均完成的结算画面：

<img src="photos/2-2-1.png" alt="2-2-1" style="zoom:33%;" />

啊总算是结束了RSA，虚了。

---

## DLP部分（30'）（×）

> [EZDLP](https://ctf.zjusec.com/games/5/challenges)

根据课上讲的DLP知识：

DLP（离散对数问题）：给定 $g^x \equiv y (\operatorname{mod} p)$ 中的 $g,y,p$，其中 $p$为大素数，求解 $x$.

是困难问题，目前无法多项式复杂度时间内解决

Diffie-Hellman密钥交换协议：

首先由参与方A,B公开参数$g,p$，并分别随机生成$x_A,x_B$，

接着分别计算各自的公钥：$y_A = g^{x_A} (\operatorname{mod} p), y_B = g^{x_B} (\operatorname{mod} q)$

最后是确认：协商密钥为$y_B^{x_A} \equiv  y_A^{x_B} \equiv g^{x_Ax_B} (\operatorname{mod} p)$

<br/>

攻击方法：

* cado-nfs工具求解
* 大步小步算法（BSGS算法）
* Pohlig-Hellman算法



BSGS算法：

- 对于  $g^x \equiv y (\operatorname{mod} p), 0<x\leq m$ 的DLP 问题，可在$O(\sqrt{m})$的时间复杂度和$O(\sqrt{m})$的空间复杂度内求解

* 流程：

  1. 设$x = \sqrt{m}x_0+x_1(0\leq x_0,x_1\leq \sqrt{m}) \Longrightarrow g^{\sqrt{m}x_0+x_1} \equiv y (\operatorname{mod} p)\Longrightarrow g^{\sqrt{m}x_0} \equiv yg^{-x_1} (\operatorname{mod} p)$

  2. 两边分别去计算并存储所有$x_0,x_1$代入后的值并进行比较，如果有一项对应相等就破解出了$x_0,x_1$，从而得出$x$.

     

Pohlig-Hellman算法：（适用于$p-1$是光滑的情况，即$p-1 = \Pi^{k}_{i=1} p_i^{\alpha_i}$，其中的$p_i$都很小）

* 流程：
  1. $p-1 = \Pi^{k}_{i=1} p_i^{\alpha_i}$，并且对每个$p_i$，设$x =\sum\limits_{j = 0}^{\alpha_i-1} x_j*p_i^{j} (\operatorname{mod} p_i^{\alpha_i})$，
  2. $g^x \equiv b (\operatorname{mod} p )\Longrightarrow g^{\frac{p-1}{p_i^t}*x} \equiv b^{\frac{p-1}{p_i^t}}(\operatorname{mod} p )$，其中$0<t<\alpha_i$. 记$A = g^{\frac{p-1}{p_i^t}}, B =  b^{\frac{p-1}{p_i^t}}$，则$A^x\equiv B(\operatorname{mod} p )$
  3. 由于$A^{p_i^t}\equiv 1(\operatorname{mod} p ) \Longrightarrow A^{\sum\limits_{j=0}^{t-1}x_j*p_i^j}\equiv B(\operatorname{mod} p )$，所以考虑从$t=1$开始到$\alpha_i$，通过枚举计算出每一个$x_j$，从而得出$x (\operatorname{mod} p_i^{\alpha_i})$的值，用这些值构造CRT求解即可得到$x(\operatorname{mod} p-1)$的值.



先看题目源码：

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5
from secret import flag

def pad(x, length):
    return x + (length - len(x) % length) * b'\x00'

p = 960494008017250155494739990397196249930200062145145133132556398221074529657304218221253517153928380265486339083177542201148993799925721673833333778621388110957986908045712612233794551809
x = getPrime(500)
g = 3
c = pow(g, x, p)

aes = AES.new(key = md5(str(x).encode()).digest(), mode = AES.MODE_ECB)
ct = aes.encrypt(pad(flag, 16))
print(f"c = {c}")
print(f"ct = {ct}")

'''
c = 505527904713564983625416248872210831215228354175257237841602581321675204643681129570897695080321118656513647239718859773976453054734892142640867733520305568808093022238369199760987416665
ct = b'qBS\x84\xfc"\xee$\xb2d\xba\xeb\x00\xf7\xf4\xa4\x91\x90<N\x1a\xb0\xa5>\xdc^\xe3I\xc3\xecc\x1e'
'''
```



因为`x = getPrime(500)`，所以不方便使用BSGS，时间复杂度过于高了.

$p-1 = 2^{518}*1119326809698249181662206673457$

用了yafu发现是个大素数，有点难办.

```bash
PS D:\Downloads\yafu> ./yafu-x64.exe "factor(1119326809698249181662206673457)"

fac: factoring 1119326809698249181662206673457
fac: using pretesting plan: normal
fac: no tune info: using qs/gnfs crossover of 95 digits
div: primes less than 10000
fmt: 1000000 iterations
Total factoring time = 0.0060 seconds

***factors found***

P31 = 1119326809698249181662206673457

ans = 1
```

所以只剩一个素数了，p-1看起来也不是很适合？算了先试一下吧.

汗流浃背了，cado-nfs也使不出来Pohlig-Hellman攻击.

<img src="photos/2-3-0.png" alt="2-3-0" style="zoom: 50%;" />



所以自己写一个试试：

（写崩了）

```python
import hashlib
import itertools
import string
import re
import gmpy2
import math
import requests 
from pwn import *
import numpy as np
from math import isqrt, gcd
from fractions import Fraction
import Crypto.Util.number
import sympy
from collections import defaultdict

p = 960494008017250155494739990397196249930200062145145133132556398221074529657304218221253517153928380265486339083177542201148993799925721673833333778621388110957986908045712612233794551809
# x = getPrime(500)
# 已知p-1 = 2^518 * 1119326809698249181662206673457，所以看起来P-H算法更合适.
g = 3
c = 505527904713564983625416248872210831215228354175257237841602581321675204643681129570897695080321118656513647239718859773976453054734892142640867733520305568808093022238369199760987416665
ct = b'qBS\x84\xfc"\xee$\xb2d\xba\xeb\x00\xf7\xf4\xa4\x91\x90<N\x1a\xb0\xa5>\xdc^\xe3I\xc3\xecc\x1e'

p_list = [2,1119326809698249181662206673457]
por = 518 # 2的幂次

def pohlig_hellman(g, h, p, p_list, por):
    x_list = []
    for prime in p_list:
        if prime == 2:
            e = por
        else:
            e = 1
        pe = prime ** e
        g1 = pow(g, (p - 1) // pe, p)
        h1 = pow(h, (p - 1) // pe, p)
        x1 = 0
        for k in range(e):
            h2 = pow(h1 * pow(g1, -x1, p), prime ** (e - k - 1), p)
            d = 0
            while pow(g1, d * (prime ** (e - k - 1)), p) != h2:
                d += 1
            x1 += d * (prime ** k)
        x_list.append((x1, pe))
    x, mod = 0, 1
    for xi, mi in x_list:
        x += xi * mod * pow(mod, -1, mi)
        mod *= mi
    return x % mod

x = pohlig_hellman(g, c, p, p_list, por)
print(f"x = {x}")

# 跑不出来结果，哎
```



## Bonus（15'）（√×）

> 请列举出除课上讲的之外2-3种RSA或者DLP相关攻击并介绍其原理，最好附带exp（如ECC特定相关攻击）

课上已经讲过的是：

- 分解攻击
- 共模攻击
- 小公钥指数攻击
- 小私钥指数攻击
- $dp,dq$泄露攻击
- 相关消息攻击
- 数论变换
- 高 / 低位泄露攻击

### RSA其他例子

> 参考文献：Dan Boneh. Twenty years of attacks on the RSA cryptosystem. *Notices of the American Mathematical Society (AMS)*, 46(2):203–213, 1999.
>

#### Blinding

假设我的私钥：$(N,d)$，公钥：$(N,e)$，攻击者希望被我签名的信息是$m$.

现在攻击者挑选了一个随机的$r$，并经过了以下处理把$m' = r^eM(\operatorname{mod}N)$传给我.

于是我提供了对$m'$的签名$s'$，但这样一来就会被攻击从而获取正常签名的$s$，这是因为：

$m' = mr^e(\operatorname{mod}N) \Longrightarrow s' = (m')^d = (mr^e)^d=m^dr^{de}\equiv m^dr(\operatorname{mod}N) $

（欧拉定理，$ de \equiv 1(\operatorname{mod} \phi(N) \Longrightarrow r^{ed-1}\equiv 1 (\operatorname{mod} N)$）

所以想要知道$s=m^d(\operatorname{mod} N)$，只需要计算$s'/r(\operatorname{mod} N)$ 即可.

payload很好写所以不写了



### Lab1 RSA - 高位泄露攻击

（试着做一下lab 1的RSA题目算吗?之前没选RSA而是做了DSA）

题目：Leaked RSA Key

> 雨夜，卢浮宫地下的羊皮纸霉味与血腥气在档案库里缠绵，首席修复师艾琳·德·维特倒在文艺复兴的尘埃中，她的指尖凝固在键盘"RSA-PKCS#1"的凹痕上，烧焦的屏幕幽幽浮出半截密钥——
>
> ```
> -----BEGIN RSA PRIVATE KEY-----
> MIGrAgEAAiEAwmNq5cPY5D/7l6sJAo8arGwL9s09cOvKKBv/6X++MN0CAwEAAQIgGAZ5m9RM5kkSK3i0MGDHhvi3f7FZPghC2gY...
> ```
>
> 如同被撕碎的魔法契约，那些省略号里沉睡着达芬奇《机械天使的密语》手稿的终极秘密。她染血的掌心紧攥的便签上，十六进制密文`1c194cd4f48d77b2e14cace43869bea17615ab23da0ef63b7bf56116ad3ac93b`像一串冰冷的诅咒，这是凶手盗取末日兵器蓝图时被监控拍下的罪证视频，却被封存在RSA的数学牢笼中。
>
> 我在现场拾起她未写完的笔记："他们以为密钥只是数字...却不知PKCS#1的ASN.1结构是唤醒机械天使的祷文..."，血渍晕染了后半句。此刻，残缺的PEM文件在证物台上泛着冷光，头部清晰的模数n与指数e是达芬奇留下的密码锁齿，而消逝在省略号中的素数p和q，正是凶手刻意抹去的钥匙齿痕。十六进制密文在投影仪上投出诡谲的波纹，仿佛五百年前的机械齿轮在黑暗中重新啮合——只有让破碎的DER编码重生，让PKCS#1的骨架从PEM残片中完整站起，才能听见素数的低语破译密文，让视频里的凶手在蓝光中显形，让吞噬光的机械在《启示录》坐标前停止心跳...
>
> 雨点敲打彩绘玻璃，像倒计时的秒针。卢浮宫穹顶的鸽群突然惊飞，散落的羽毛在密钥片段旁排成一行隐形的警告：当模数在标准格式中复活时，真相将刺穿所有阴影。

翻译成正常人能看懂的话是：

```python
n = 'MIGrAgEAAiEAwmNq5cPY5D'
e = '7l6sJAo8arGwL9s09cOvKKBv'
# p,q = 6X++MN0CAwEAAQIgGAZ5m9RM5kkSK3i0MGDHhvi3f7FZPghC2gY... （残缺）
cipher = 0x1c194cd4f48d77b2e14cace43869bea17615ab23da0ef63b7bf56116ad3ac93b
```

此外提到了PKCS#1的ASN.1结构，需要还原“破碎的DER编码”.

对于RSA私钥，其ASN.1结构如下：

```
RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
}
```

似乎没什么特别之处. 感觉是一个私钥高位泄露的攻击.

（没时间了，中途放弃）

