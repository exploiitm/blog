+++
title = "veiled_xor"
date = 2025-07-07
authors = ["Sanat"]
+++

# Challenge: veiled_xor

## Challenge Overview

We are given the following parameters for an RSA encryption:

- RSA modulus `n`
- Ciphertext `c`
- An additional mysterious value: `veiled_xor`

The challenge states that `n = p * q` and `veiled_xor = p ^ rev_q`, where:

- `p` and `q` are 1024-bit primes.
- `rev_q` is the bitwise reversal of `q`.

The goal is to recover the prime factors `p` and `q` to decrypt the ciphertext.

## Vulnerability

The core vulnerability is the leakage of information through the `veiled_xor` value. This value creates a direct mathematical relationship between the bits of `p` and the reversed bits of `q`, which we can exploit to reconstruct the primes.

## Strategy: Smart Bit-by-Bit Construction

A brute-force attack is infeasible given the 1024-bit key size. Instead, we will be constructing the primes bit-by-bit from both ends simultaneously.

At each step `k` (from `k=1` to `k=511`), we determine the bits at position `k` (from the LSB side) and `1023-k` (from the MSB side) for both `p` and `q`.

- **`p_base`, `q_base`:** These represent the partially constructed primes at the beginning of a step. All unknown middle bits are treated as zero.
- **Candidates:** We maintain a list of all `(p, q)` pairs that remain plausible after each step's filtering.

## Implementation: `exploit.c`

The logic is implemented in C to leverage its speed for bitwise operations and the GMP library for handling large numbers. The multi-threaded approach allows us to check the expanding list of candidates efficiently.

### The Core Loop: Derivation and Filtering

Instead of naively trying all 16 combinations for the four new bits (`p[k]`, `q[k]`, `p[1023-k]`, `q[1023-k]`) at each step, we use an algebraic shortcut to reduce the possibilities to just **two**.

#### 1. Derivation Logic (`thread_worker_optimized`)

For each candidate `(p_base, q_base)` from the previous step, we combine two fundamental equations:

**Equation A (from `n = p * q`):**
The `k`-th bit of the product `n` is the XOR sum of the `k`-th bits of the inputs and the final carry bit from the lower positions.

> `n[k] = p[k] ^ q[k] ^ carry_k`

**Equation B (from `veiled_xor`):**
The `k`-th bit of `p` is related to the `(1023-k)`-th bit of `q`.

> `p[k] = veiled_xor[k] ^ q[1023-k]`

By substituting Equation B into Equation A, we can solve for a direct relationship between the two unknown `q` bits:

`n[k] = (veiled_xor[k] ^ q[1023-k]) ^ q[k] ^ carry_k`

Rearranging this gives us our magic formula:

`q[k] ^ q[1023-k] = n[k] ^ veiled_xor[k] ^ carry_k`

The `carry_k` term is the `k`-th bit of the product of the parts we already know: `prod = p_base * q_base`.

So, we define a target value:
`target_q_xor = n[k] ^ prod[k] ^ veiled_xor[k]`

This gives us the final relationship:
`q[1023-k] = q[k] ^ target_q_xor`

#### 2. Generating the Two Candidates

This relationship means we only have two scenarios to test for each `(p_base, q_base)`:

1. **Guess `q[k] = 0`:** This forces `q[1023-k] = target_q_xor`.
2. **Guess `q[k] = 1`:** This forces `q[1023-k] = 1 ^ target_q_xor`.

Once we have a pair of `q` bits, we can instantly find the corresponding `p` bits using the `veiled_xor` leak again:

- `p[k] = veiled_xor[k] ^ q[1023-k]`
- `p[1023-k] = veiled_xor[1023-k] ^ q[k]`

We now have a complete set of four new bits, which we add to `p_base` and `q_base` to form a new candidate pair `(p_new, q_new)`.

#### 3. The MSB Filter

For each of the two new candidate pairs, we apply a crucial filter to discard impossible paths:

1. **Top Bits Check:** The product of the most significant bits of our candidate (`top_prod`) must not exceed the most significant bits of the real `n` (`top_n`).
2. **Carry Margin:** The difference (`top_n - top_prod`) is due to carries from the unknown middle. This difference must be within a plausible bound: `diff < 2^(k+2)`.

If a `(p_new, q_new)` pair passes this filter, it is added to the list of candidates for the next iteration.

### Final Verification and Decryption

After the loop completes at `k=511`, we are left with several  plausible, fully-formed candidate pairs. We then perform a final, exact check:

1. Loop through every surviving candidate `(p, q)`.
2. Check if `p * q` is **exactly equal** to `n`.
3. Check if `p ^ rev_q` is **exactly equal** to `veiled_xor`.

Only one candidate will satisfy both conditions. Once we find this correct pair:

- We compute the private key: `d = inverse(e, (p-1)*(q-1))`
- We decrypt the ciphertext: `m = pow(c, d, n)`
- We convert the resulting message `m` from an integer to a string to reveal the flag.

**Flag:** `bi0sCTF{X0rcery_R3ve3rsing_1s_4n_4rt_2d3e3d}`

*Reference: [here](https://github.com/toby-bro/Writeups/blob/main/bi0sCTF2025/veiled_xor/)*

