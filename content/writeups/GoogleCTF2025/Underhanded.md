+++
title = "Underhanded"
date = 2025-07-23
authors = ["Swaminath Shiju"]
+++

# Underhanded GCTF25
### Description

Proudly sharing our Python implementation of AES. By the way, we sneakily hid a backdoor. Can you see sharp and see what went wrong?

```python
def challenge():
    k = os.urandom(16)
    aes = AES(k)

    # I will encrypt FIVE messages for you, that's it.
    for _ in range(5):
        m = bytes.fromhex(input('📄 '))
        c = aes.encrypt(m)
        print('🤫', c.hex())

    _k = bytes.fromhex(input('🔑 '))
    if k != _k: raise Exception('incorrect guess!')
```

### Solution

Here the gist of the question is to guess the custom AES's key from 5 chosen plaintext ciphers 16 times. Now we need to hunt for backdoors in the AES implementation.

Looking into the encrypt function

```python
def encrypt(self, m: bytes) -> bytes:
    c = bytearray(m)
    c = self.add_round_key(c, 0)
    for r in range(1, self.n_rounds):
        c = self.sub_bytes(c)
        c = self.shift_rows(c)
        c = self.mix_columns(c)
        c = self.add_round_key(c, r)
    c = self.sub_bytes(c)
    c = self.shift_rows(c)
    c = self.add_round_key(c, self.n_rounds)
    return bytes(c)
```

this seems pretty normal, but when we look into `shift_rows` the first statement looks like it has a "typo".

```python
def shift_rows(self, m: bytearray) -> bytearray:
    m[+0], m[+4], m[+8], m[12] = m[+0], m[+4], m[-8], m[12]
    m[+1], m[+5], m[+9], m[13] = m[+5], m[+9], m[13], m[+1]
    m[+2], m[+6], m[10], m[14] = m[10], m[14], m[+2], m[+6]
    m[+3], m[+7], m[11], m[15] = m[15], m[+3], m[+7], m[11]
    return m
```

That `m[-8]` is supposed to be a `m[+8]`. Another backdoor is simply how multiple blocks of plaintext (i.e length of PT > 16). For instance looking at shift rows it clearly operates, uses only the first 16 bytes (other than `m[-8]` of course).

The same is true for `mix_columns` as well.

```python
def mix_columns(self, m: bytearray) -> bytearray:
    for i in range(0, 16, 4):
        t = m[i+0] ^ m[i+1] ^ m[i+2] ^ m[i+3]
        u = m[i+0]
        m[i+0] ^= t ^ xtime(m[i+0] ^ m[i+1])
        m[i+1] ^= t ^ xtime(m[i+1] ^ m[i+2])
        m[i+2] ^= t ^ xtime(m[i+2] ^ m[i+3])
        m[i+3] ^= t ^ xtime(m[i+3] ^ u)
    return m
```

So if we send multiple blocks, every block other than the first one is only affected by `add_round_key` and `sub_bytes`. 

Now we can bring both of them together to create an exploit. Denoting resulting cipher text as $c_0, c_1,\cdots$, the input to the last shift rows as $s_0,s_1,\cdots$  and the keys using $k_0,k_1,\cdots$. Now looking at how we use the `m[-8]` to exploit the last `add_round_key`. 
`r = (n-8)%16`

$$
\begin{aligned}
c_8&=s_r\oplus k_{10}[8] \\
c_r&=s_r\oplus k_{10}[r] \\ \ \\
c_r\oplus c_8 &=k_{10}[8]\oplus k_{10}[r]
\end{aligned}
$$
Here $n$ is the total plaintext length. This gives us 5 relations for the bytes in $k_{10}$. So if we guess a value for $k_{10}[8]$ that gives us 6 bytes in $k_{10}$.

Now we can try to reverse the key-scheduling to get more bytes in the other round keys. We have multiple possible choices for these 6 bytes I chose `0, 4, 5, 8, 9, 13` bytes. Now looking at the relevant parts of the key scheduling algorithm.

$$
\begin{aligned}
k_{n}[0]&=k_{n-1}[0]\oplus \sigma(k_{n-1}[13])\oplus \text{RCON}[n-1][0]\\ \ \\
k_{n}[4]&=k_{n-1}[4]\oplus k_{n}[0]\\ \ \\
k_{n}[5]&=k_{n-1}[5]\oplus k_{n}[1]\\ \ \\
k_{n}[8]&=k_{n-1}[8]\oplus k_{n}[4]\\ \ \\
k_{n}[9]&=k_{n-1}[9]\oplus k_{n}[5]\\ \ \\
k_{n}[13]&=k_{n-1}[13]\oplus k_{n}[9]
\end{aligned}
$$

Here $\text {RCON}$ is an array of constants. So if we have $k_{10}[0]$,$k_{10}[4]$,$k_{10}[5]$,$k_{10}[8]$,$k_{10}[9]$,$k_{10}[13]$ we can derive $k_9[0]$,$k_9[4]$,$k_9[8]$,$k_9[9]$,$k_9[13]$. We clearly lose a byte but as we keep going backward we get.

|     |      0      |      4      |      5      |      8      |      9      |      13      |
| --- |:-----------:|:-----------:|:-----------:|:-----------:|:-----------:|:------------:|
| 10  | $k_{10}[0]$ | $k_{10}[4]$ | $k_{10}[5]$ | $k_{10}[8]$ | $k_{10}[9]$ | $k_{10}[13]$ |
| 9   | $k_{9}[0]$  | $k_{9}[4]$  |             | $k_{9}[8]$  | $k_{9}[9]$  | $k_{9}[13]$  |
| 8   | $k_{8}[0]$  | $k_{8}[4]$  |             | $k_{8}[8]$  |             | $k_{8}[13]$  |
| 7   |             | $k_{7}[4]$  |             | $k_{7}[8]$  |             |              |
| 6   |             |             |             | $k_{6}[8]$  |             |              |

Now we look at the byte xor'ed with $k_j[8]$ in a later block denote it by C.
Then
$$
C=k_{10}[8]\oplus\sigma(k_9[8]\oplus \sigma(k_8[8]\cdots\sigma(k_0[8]\oplus P)))
$$

we can move the known bytes to the left hand side since $\sigma$ and $\oplus$ are reversible.

$$
C'=k_{5}[8]\oplus\sigma(k_4[8]\oplus \sigma(k_3[8]\cdots\sigma(k_0[8]\oplus P)))
$$
The naive brute force now would need $2^8 \times 2^{8\times 6}=2^{56}$ guesses (1 byte for $k_{10}$ and then 6 bytes from the previous round keys).

However we can be clever here, since they are reversible we can rewrite it as.

$$
\sigma^{-1}(\sigma^{-1}(\sigma^{-1}(C'\oplus k_5[8])\oplus k_4[8])\oplus k_3[8]) = k_2[8]\oplus \sigma(k_1[8]\oplus\sigma(k_0[0]\oplus P))
$$
Now we can brute force each side separately using a meet in the middle attack needing is more feasible. We can shorten the time some more by leveraging more information from the CT.

If we look at another byte xor'd with $k_j[8]$ we get a similar equation

$$
\sigma^{-1}(\sigma^{-1}(\sigma^{-1}(C''\oplus k_5[8])\oplus k_4[8])\oplus k_3[8]) = k_2[8]\oplus \sigma(k_1[8]\oplus\sigma(k_0[0]\oplus P'))
$$
Xor-ing both we get

$$
\begin{aligned}
\sigma^{-1}(\sigma^{-1}(\sigma^{-1}(C'\oplus k_5[8])\oplus k_4[8])\oplus k_3[8]) \oplus \sigma^{-1}(\sigma^{-1}(\sigma^{-1}(C''\oplus k_5[8])\oplus k_4[8])\oplus k_3[8]) = \\ \sigma(k_1[8]\oplus\sigma(k_0[0]\oplus P')) \oplus \sigma(k_1[8]\oplus\sigma(k_0[0]\oplus P))
\end{aligned}
$$

This eliminated a variable without minimal impact in check time but almost halfs number of iterations required. 

Now with the entire $k_j[8]$ and $k_{10}[4]$ known we can derive $k_j[4]$ and then $k_j[0]$, $k_j[13]$, $k_j[9]$ and $k_j[5]$. Now we need to guess a byte 10 times for the remaining bytes which are easily doable guesses to get all the remaining key bytes.


> Note: You need a sufficiently beefy computer to do this 16 times in 300s


