+++
title = "Braiding Bad"
date = 2025-06-27
authors = ["Swaminath Shiju"]
+++


### Description

Once upon a time , a braid decided to break bad ...

```py
import random
import string
import hashlib
from Crypto.Util.number import bytes_to_long

message = <REDACTED>

n = 100
Bn = BraidGroup(n)
gs = Bn.gens()
K = 32

gen = gs[n // 2 - 1]
p_list = [gen] + random.choices(gs, k=K-1)
p = prod(p_list)
print(f"p: {list(p.Tietze())}")

a = prod(random.choices(gs[:n//2-2], k=K))
q = a * p * a^-1
print(f"q: {list(q.Tietze())}")

br = prod(random.choices(gs[n//2 + 1:], k=K))
c1 = br * p * br^-1
c2 = br * q * br^-1

h = hashlib.sha512(str(prod(c2.right_normal_form())).encode()).digest()

original_message_len = len(message)
pad_length = len(h) - original_message_len
left_length = random.randint(0, pad_length)
pad1 = ''.join(random.choices(string.ascii_letters, k=left_length)).encode('utf-8')
pad2 = ''.join(random.choices(string.ascii_letters, k=pad_length - left_length)).encode('utf-8')
padded_message = pad1 + message + pad2

d_str = ''.join(chr(m ^^ h) for m, h in zip(padded_message, h))
d = bytes_to_long(d_str.encode('utf-8'))

print(f"c1: {list(c1.Tietze())}")
print(f"c2: {d}")
```

### Solution

The challenge uses a simple encryption based on Braid groups to encrypt the flag.

`Bn` is a braid group of order 100. `gs` is the list of generators, it multiplies `K` random generators to make an element `p` of `Bn`.
`p.Tietze()` simply gives the list of generators used to create `p`.

For example if $\text{p}=\sigma_1\sigma_{11}\sigma_{34}^{-1}\sigma_4^2$ then $$\text{p.Tietze()}=(1,11,-34,4,4)$$
> Note: The Tietze of `p` would have only positive elements since its made from generators.

This means we can directly use the printed value to get the `p` from the printed `Tietze`. The final encoding is done by converting the normal form of `c2` into bytes, sha512 hashing it and then xor-ing it with the flag. For the purposes of this question we can take `normal_form` as simply a black box to convert a group element to bytes.

So getting the flag reduces to finding `c2`. Assume $\text{br}=\sigma_{a_1}\sigma_{a_2}\cdots\sigma_{a_{32}}$ then `c1` would be $\left(\sigma_{a_1}\sigma_{a_2}\cdots\sigma_{a_{32}}\right)\cdot p \cdot\left(\sigma_{a_{32}}^{-1}\sigma_{a_{31}}^{-1}\cdots\sigma_{a_1}^{-1}\right)$. The printed Tietze list would simply be $$(a_1,a_2,\cdots,a_{32},[\,\, p\,\,],-a_{32},-a_{31},\cdots,-a_1)$$
We can get `br` from the first 32 elements of the Tietze. Now since we have `br` and `q` we get `c2` and then just pass it through the encryption to get the xor valued need to decrypting.

> **Note:** It is possible for the end point of `p` to cancel out with the end-point of `c1`. This is improbable but easily fixable using the Tietze of `p`

Final solve script

```py
from sage.groups.braid import BraidGroup
from sage.all import prod
import hashlib

print("READY")
Bn = BraidGroup(100)

# not required unless cancellation happens
# p = Bn(<Tietze of p>)
# c1 = Bn(<Tietze of c1>)

q = Bn(<Tietze of q>)
br = Bn(<Tietze of c1>[:32])
c2 = br * q * br**(-1)

from Crypto.Util.number import long_to_bytes

ct = long_to_bytes(<encoded>).decode('utf-8')
print("READY")

h = hashlib.sha512(str(prod(c2.right_normal_form())).encode()).digest()
print("".join(chr(a ^ ord(b)) for a, b in zip(h, ct)))
```
