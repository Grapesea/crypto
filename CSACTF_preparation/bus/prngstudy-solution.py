from pwn import *
from hashlib import sha256
import itertools
import ast

# forward 127.0.0.1:3100
conn = remote('127.0.0.1', 3100)



pow_charset = string.ascii_letters + string.digits
pow_length = 4
def find_xxxx(suffix, target_hash):
    for candidate in itertools.product(pow_charset, repeat=pow_length):
        xxxx = ''.join(candidate)
        combined = xxxx + suffix
        hash_result = sha256(combined.encode()).hexdigest()
        if hash_result == target_hash:
            return xxxx
    return None

# input: (proof of work)
# sha256(XXXX + MDBieoFTKyVJo8IM) == fcc7662adbdf4d05ccd2201814685daf13d219f19eff49329be78ba8ccb4b668
# Give me XXXX:
def process_proof_of_work():
    line_sha256 = conn.recvline().decode()
    # print("Received:", line_sha256.strip())
    suffix = line_sha256.split(' + ')[1].split(')')[0]
    digest = line_sha256.split('== ')[1].strip()
    print("Suffix:", suffix)
    print("Digest:", digest)
    result = find_xxxx(suffix, digest)
    if result is None:
        raise Exception("Failed to find XXXX")
    conn.sendlineafter(b"Give me XXXX:", result.encode())

# a * d[0] === d[1] (mod n)
# for a * D === T (mod n)
# g = gcd(D, n)
# then D/g * a === T/g (mod n/g)
# so a = (T/g) * inv(D/g, n/g) (mod n/g)
def exgcd(D, T, n):
    g = math.gcd(D, n)
    if T % g != 0:
        return None
    D //= g
    T //= g
    n //= g
    inv = pow(D, -1, n)  # Modular inverse of D mod n
    a = (T * inv) % n
    return a

def try_solve_level1(known, d, n):
    # a * d[0] === d[1] (mod n)
    # a * d[1] === d[2] (mod n)
    # a * d[2] === d[3] (mod n)
    # a * d[3] === d[4] (mod n)

    possible_a = [
        exgcd(d[0], d[1], n),
        exgcd(d[1], d[2], n),
        exgcd(d[2], d[3], n),
        exgcd(d[3], d[4], n)
    ]
    possible_a = [a for a in possible_a if a is not None]
    if not possible_a:
        return None
    
    # known[1] = a * known[0] + b (mod n)
    # b = known[1] - a * known[0] (mod n)
    possible_b = []
    for a in possible_a:
        b = (known[1] - a * known[0]) % n
        possible_b.append(b)

    # print(f"Possible a: {possible_a}")
    # print(f"Possible b: {possible_b}")
    
    # Check if all pairs (a, b) are valid
    for a, b in zip(possible_a, possible_b):
        valid = True
        for i in range(len(known) - 1):
            # print(f"Checking: {a} * {known[i]} + {b} % {n} == {(a * known[i] + b) % n}")
            # print(f"Expected: {known[i + 1]}")
            get_next = (a * known[i] + b) % n
            if get_next != known[i + 1]:
                # print(f"Invalid: {a} * {known[i]} + {b} % {n} != {known[i + 1]}")
                new_n = math.gcd(abs(get_next - known[i + 1]), n)
                # print(f"New n: {new_n}")
                Q = try_solve_level1(known, d, new_n)
                if Q is not None:
                    return Q
                valid = False
                break
        if valid:
            return a, b, n

    return None


def solve_level1(known):
    d = [known[i+1] - known[i] for i in range(len(known)-1)]
    T0 = d[1]*d[1] - d[0]*d[2]
    T1 = d[2]*d[2] - d[1]*d[3]
    T2 = d[3]*d[3] - d[2]*d[4]
    n = math.gcd(math.gcd(abs(T0), abs(T1)), abs(T2))
    # print(f"n: {n}")
    
    return try_solve_level1(known, d, n)

def level_1():
    conn.sendlineafter(b"Level: ", b"1")
    conn.recvline()
    line_leak = conn.recvline().decode()
    known = ast.literal_eval(line_leak.strip())
    print("Known values:", known)
    a,b,n = solve_level1(known)
    print(f"Found a: {a}, b: {b}, n: {n}")
    output = [known[0]]
    for i in range(19):
        next_value = (a * output[-1] + b) % n
        output.append(next_value)
    print("Output:", output)
    for value in output:
        conn.sendlineafter("guess:", str(value).encode())


process_proof_of_work()
level_1()
conn.interactive()