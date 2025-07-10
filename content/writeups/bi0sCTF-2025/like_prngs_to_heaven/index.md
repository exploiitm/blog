+++
title = "Like PRNGs to Heaven"
date = 2025-07-10
authors = ["Sanat"]
+++

#

## Challenge Overview

Our aim in this challenge is to interact with a game system that presents us with several options:

* `get_encrypted_flag` - Retrieves the encrypted flag (**costs 50 HP**)
* `perform_deadcoin` - Play a minigame to gain HP (**+20 HP if successful, no cost**)
* `call_the_signer` - Get an ECDSA signature for a message (**costs 20 HP**)
* `level_restart` - Restart the level (**resets HP to 100, no cost**)
* `level_quit` - Exit the game

The challenge revolves around ECDSA signatures based on Elliptic Curve Cryptography. For a comprehensive understanding of ECDSA, refer to this excellent video: [here](https://www.youtube.com/watch?v=NF1pwjL9-DE)

## Vulnerabilities Analysis

There are numerous vulnerabilities across all the challenge files:

### 1. Weak RMT (Mersenne Twister) Implementation - RMT.py

```python
def seedMT(self, seed):
    num = seed
    self.index = self.n
    for _ in range(0,51):
        num = 69069 * num + 1
    g_prev = num
    for i in range(self.n):
        g = 69069 * g_prev + 1
        self.MT[i] = g & self.d
        g_prev = g
```

This implementation uses a weak seeding algorithm (Ripley's seeding) that generates the entire 624-word initial state from a single 32-bit seed. The twist() and tempering operations are mathematically reversible if we have enough consecutive outputs from get\_num().

### 2. Flawed supreme\_RNG - chall.py

```python
@staticmethod
def supreme_RNG(seed: int, length: int = 10):
    while True:
        str_seed = str(seed) if len(str(seed)) % 2 == 0 else '0' + str(seed)
        sqn = str(seed**2)
        mid = len(str_seed) >> 1
        start = (len(sqn) >> 1) - mid
        end = (len(sqn) >> 1) + mid   
        yield sqn[start : end].zfill(length)
        seed = int(sqn[start : end])
```

This middle-square method is completely deterministic and predictable. The seed is derived from:

```python
CORE = 0xb4587f9bd72e39c54d77b252f96890f2347ceff5cb6231dfaadb94336df08dfd
RNG_seed = simple_lcg(CORE)
```

### 3. Nonce Generation Leaks - full\_noncense\_gen()

```python
def full_noncense_gen(self) -> tuple:
    k_, cycle_1 = self.sec_real_bits(32)
    _k, cycle_2 = self.sec_real_bits(32)

    benjamin1, and1, eq1 = self.partial_noncense_gen(32, 16, 16)
    benjamin2, and2, eq2 = self.partial_noncense_gen(32 ,16 ,16)
```

The function returns:

```
n1 = [and1, eq1] and n2 = [and2, eq2]  # Info about benjamin values
cycles = [cycle_1, cycle_2]            # Heat cycles revealing RMT advancement
```

This leaks substantial information about the nonce structure, particularly the benjamin1 and benjamin2 values which can be recovered using the equation:

```python
equation = term ^ ((term << shift) & _and)
```

### 4. ECDSA Signature Information

The sign function returns:

```python
return (r, s, n1, n2, cycles)
```

The ECDSA signature equation is:

$s = k^{-1} \cdot (H(m) + r \cdot d) \mod n$

Where:

* `s`: The signature value
* `k`: The nonce (ephemeral private key)
* `H(m)`: SHA256 hash of the message
* `r`: x-coordinate of the point kG
* `d`: The private key
* `n`: Order of the elliptic curve (secp256k1)

## The Exploit

### Step 1: Decay supreme\_RNG to Zero

Through experimentation, we discover that after exactly 374 restarts, the supreme\_RNG yields "0000000000". This happens because the middle-square method eventually converges to zero:

### Step 2: Exploit the Deadcoin Game

```python
feedbacker_parry = int(next(self.n_gen))  # = 0
style_bonus = feedbacker_parry ^ (feedbacker_parry >> 5)  # = 0 ^ 0 = 0
power = pow(base, style_bonus, speed)  # = 2^0 mod speed = 1
```

When we see power = 1, we know the answer is 0. Playing deadcoin three times with answer "0" gives us:

```python
blood = self.Max_Sec.get_num()  # RMT output
```

These three consecutive RMT outputs allow us to reverse the seed.

### Step 3: Reverse RMT Seed with Z3

Using Z3 solver, we model:

* An unknown 32-bit seed
* The Ripley seeding process to generate initial state
* The twist operation
* The tempering function

We constrain the first three outputs to match our collected BLOOD\_IDs and solve for the seed.

### Step 4: Recover Partial Nonces

With the RMT seed recovered, we can predict future outputs. For each signature, we:

* Use the heat cycles to advance our local RMT appropriately
* We recover `k_` and `_k` values from RMT
* Use Z3 to solve for benjamin values from the leaked equations

### Step 5: Extended Hidden Number Problem (EHNP)

Now we have partial information about both the private key and nonces. Following Joseph Surin's paper [here](https://eprint.iacr.org/2023/032.pdf), we apply the Extended Hidden Number Problem algorithm.

**ECDSA-EHNP Equation Setup**

Start with:

$s[i] \cdot k[i] \equiv H(m) + r[i] \cdot d \pmod{n}$

Rearranged:

$-r[i] \cdot d + s[i] \cdot k[i] \equiv H(m) \pmod{n}$

Known structures:

$d = 2^{148} \cdot d_1 + 2^{21} \cdot d_2$

$k[i] = k_{bar} + 2^{232} \cdot k_1 + 2^{200} \cdot k_2 + 2^{83} \cdot k_3 + 2^{45} \cdot k_4$

Substitute:

$-r[i](2^{148} \cdot d_1 + 2^{21} \cdot d_2) + s[i](2^{232} \cdot k_1 + 2^{200} \cdot k_2 + 2^{83} \cdot k_3 + 2^{45} \cdot k_4) \equiv H(m) - s[i] \cdot k_{bar} \pmod{n}$

EHNP form:

$\alpha_i \cdot \sum 2^{\pi_j} \cdot x_j + \sum \rho_{i,j} \cdot k_{i,j} \equiv \beta_i - \alpha_i \cdot \bar{x} \pmod{p}$

We will now outsource these values to an external solver, coz why not :p
We will use `ecdsa_key_disclosure()` from Joseph Surin’s toolkit to solve.

### Step 6: Recover the Flag

```python
sha2 = sha256()
sha2.update(str(d).encode('ascii'))
key = sha2.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
```

**FLAG:** `bi0sCTF{p4rry_7h15_y0u_f1l7hy_w4r_m4ch1n3}`

---

## Key Takeaways

* The importance of proper PRNG seeding
* The power of lattice-based attacks on cryptographic systems
  
Reference:[here](https://blog.bi0s.in/2025/06/13/Crypto/Elliptic-Curves/LikePRNGStoHeaven-bi0sCTF2025/)
