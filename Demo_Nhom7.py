'''
q -> Prime Divisor
p -> prime number, that: (p - 1) % q == 0
g -> any integer (1 < g < p) that: g**q mod p == 1 and
g = h**((p - 1)/q) mod p  (h is any number less than p - 1 that g > 1)

x: Private Key, x = random number less than q 
y: Public Key, y = (g**x) mod p

Private Key can be packaged: {p,q,g,x}
Public Key can be packaged: {p,q,g,y}

Signature:
1.Message is passed through a hash function -> message digest
2.Choose any random k that: 0 < k < q
3.To Calculate r:
r = (g**k mod p) mod q
4.To Calculate s:
s = (k^(-1) (H(m) + x*r)) mod q    :H(m) -> hash message, k^(-1) is mod inverse k,q
Signature can be packaged {r,s}


Verify:
1. Calculate w = s^(-1) mod q   : s^(-1) is mod inverse s, q   Like w that: s*w mod q = 1
2. Calculate u1 = (H(m) * w) mod q
3. Calculate u2 = (r * w) mod q
4. Calculate v = ((g**u1)*(g**u2) mod p) mod q

if v == r -> the signature is verified

'''


import random
import math 
import hashlib


def is_prime(number: int) -> bool:
    if number < 2:
        return False

    scope = int(math.sqrt(number) + 1)

    for i in range(2, scope):
        if number % i == 0:
            return False
    
    return True 


def generate_prime(min_value, max_value):
    prime_number = random.randrange(min_value, max_value)
    while not is_prime(prime_number):
        prime_number = random.randrange(min_value, max_value)
    return prime_number


def find_h_paremeter(p,q):
    for h in range(1,p-1):
        if pow(h, (p-1)//q, p) > 1:
            return h
    return -1 


def mod_inverse(a,b):
    for i in range(1,b):
        if (a * i) % b == 1:
            return i
    return -1

def generate_parameter():
    q = generate_prime(1000,5000)
    p = generate_prime(1000,60000)
    while (p-1)%q != 0:
        p = generate_prime(1000,60000)

    print(f"p: {p}")
    print(f"q: {q}")

    h = find_h_paremeter(p,q)
    print(f"h: {h}")

    g = pow(h, (p-1)//q, p)
    print(f"g: {g}")

    return p, q, g
    

def generate_key_pair():
    p, q, g = generate_parameter()
    
    # Private key
    x = random.randrange(1,q-1)

    # Public key
    y = pow(g,x,p)

    print(f"x: {x}")
    print(f"y: {y}")

    return [p,q,g,x], [p,q,g,y]


def hash_message(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode('utf-8'))
    digest = sha256.hexdigest()
    hash_value = int(digest, 16)
    print(hash_value)
    return hash_value


def signature(message, private_key):
    p, q, g, x = private_key
    hash_val = hash_message(message)
    k = random.randrange(1,q-1)

    print(f"k: {k}")

    r = ((g**k)%p)%q
    s = (mod_inverse(k,q)*(hash_val + x*r)) % q

    return [r,s]


def verify(message, sign, public_key):
    p, q, g, y = public_key
    r, s = sign
    hash_val = hash_message(message)
    print(f"r: {r}")
    print(f"s: {s}")
    
    w = mod_inverse(s,q)
    u1 = (hash_val * w) % q
    u2 = (r * w) % q
    v = ((pow(g,u1) * pow(y, u2)) % p) % q 
    print(f"w: {w}")
    print(f"u1: {u1}")
    print(f"u2: {u2}")

    print(f"r: {r}")
    print(f"v: {v}")
    return r == v 


mes = "Hello World!"
private_key, public_key = generate_key_pair()

sign = signature(mes,private_key)
print(sign)
print(private_key)
print(public_key)

# Ví dụ xác minh không thành công!
# public_key = [41389, 3449, 4096, 1245125]



if (verify(mes,sign, public_key)): print("Xác minh thành công!")
else: print("Xác minh không thành công!")

# print(is_prime(4999))  # max q:
# print(is_prime(49991)) # max p: 
