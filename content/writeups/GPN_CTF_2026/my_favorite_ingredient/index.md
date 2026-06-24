+++
title = "My Favorite Ingredient"
date = 2026-06-24
authors = ["Prasanna K S"]
+++

**Category:** Reverse Engineering
**Flag:** `GPNCTF{juS7_ONe_0NstrUcTION5_Is_4LL_YoU_n3ED_MaY8e1239794fKfNdh}`

---

## 1. Overview

We are given a single 64‑bit ELF executable:

```
$ file my-favorite-ingredient
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec
PIE, NX, Partial RELRO, No canary   (symbols present)
```

The program is a classic "flag checker":

```
$ ./my-favorite-ingredient AAAA
Flag must be 64 characters long.

$ ./my-favorite-ingredient $(python3 -c 'print("A"*64,end="")')
Incorrect flag.
```

So the flag is exactly **64 bytes** long. Our job is to recover the one input
that prints `Correct flag!`.

The challenge title ("my favorite ingredient") and the flag itself
(`juS7_ONe_0NstrUcTION5_Is_4LL_YoU_n3ED`) are a hint: the checker is written
almost entirely out of a handful of **AVX2 SIMD instructions** — "just one
instruction is all you need". That styling is meant to scare you off static RE.
It doesn't have to.

---

## 2. Static analysis

Only two interesting functions exist: `main` and `verify_flag`
(plus a helper `matvec_mul_vectorized`).

### 2.1 `main`

```asm
; argv[1] length must be 64
call strlen ; cmp $0x40, %rax

lea  0x2a534(%rip), %rsi   ; -> 0x31170   (source data)
lea  0x80(%rsp),    %rbx
mov  $0x1000,       %edx   ; 0x1000 = 4096 bytes
call memcpy                ; copy a 4096-byte blob onto the stack

vmovups 0x2b512(%rip), %zmm0   ; -> 0x32170  (64 bytes)
vmovups %zmm0, 0x40(%rsp)      ; copy 64-byte "target" onto the stack

lea  0x40(%rsp), %rdi          ; flag bytes
mov  $0x40,      %esi          ; length = 64
call verify_flag               ; verify_flag(flag, 64, matrix@0x80, target@0x40)
```

Two static data regions matter:

| Region | File offset | Size | Meaning |
|--------|-------------|------|---------|
| Matrix `M` | `0x31170` | `0x1000` = 64×64 bytes | a 64×64 byte matrix |
| Target `T` | `0x32170` | `0x40` = 64 bytes | the expected output |

`verify_flag` is called as `verify_flag(rdi=flag, rsi=64, rdx=M, rcx=T)`.

### 2.2 `verify_flag` — stage 1 (per-byte affine)

The first block is pure AVX2 on the 64 input bytes:

```asm
vmovdqu (%rdi), %ymm0           ; load input
...
vpmullw  ymm3, ...              ; ymm3 = 0x00c5 broadcast  -> multiply by 197
vpand    ymm4, ...              ; ymm4 = 0x00ff broadcast  -> keep low byte
vpackuswb ...
vpaddb   ymm2, ...              ; ymm2 = 0x65   broadcast  -> add 101
```

The `vpunpck*/vpmullw/vpand/vpackuswb` dance is just a vectorized 8‑bit
multiply (16‑bit multiply, then truncate to the low 8 bits). Stripped of SIMD,
stage 1 is a simple per‑byte **affine map mod 256**:

```
t[i] = (197 * flag[i] + 101) mod 256
```

The constants come straight from `.rodata`:

```
0x31020: c5 00 ...   -> multiplier 0xC5 = 197
0x31040: ff 00 ...   -> mask 0x00FF
0x31060: 65 65 ...   -> addend 0x65 = 101
```

### 2.3 `verify_flag` — stage 2 (matrix–vector product)

The transformed vector `t` is then fed to `matvec_mul_vectorized(M, t, out)`:

```asm
lea  0x40(%rsp), %rsi   ; t  (stage-1 output)
mov  %rdx, %rdi         ; M  (the 64x64 matrix)
mov  %rsp, %rdx         ; out
call matvec_mul_vectorized
```

Inside, each vector byte `v` is first run through another affine
`a = (19*v + 223) mod 256` (note the `lea (%rax,%rax,2)` → ×3, `lea (%rax,%rcx,4)`
→ ×13… giving ×19, then `add $0xdf` → +223), and then its 8 bits are
broadcast to lane masks (`vpbroadcastd`) and used to conditionally accumulate
matrix rows. The net effect is an ordinary **matrix–vector product mod 256**.

### 2.4 `verify_flag` — stage 3 (the comparison)

The result is compared, byte by byte, against the **bitwise complement** of the
target:

```asm
mov  (%rbx), %cl
not  %cl                 ; cl = ~T[0]
cmp  %cl, (%rsp)         ; out[0] == ~T[0] ?
jne  fail
... (repeated 64 times)
```

So the accept condition is simply:

```
out[i] == (~T[i]) & 0xff      for all i in 0..63
```

---

## 3. The key insight: the whole checker is affine over ℤ/256

Compose the stages:

* Stage 1: `t = a1 ⊙ flag + b1`  (per‑byte affine)
* Stage 2: `out = M' · t + b2`   (matrix multiply + affine, all mod 256)

A composition of affine maps is affine. Therefore the *entire* checker, as a
function of the 64 input bytes, is:

```
out = A · flag + c          (mod 256)
```

for some **64×64 matrix A** and **constant vector c**, both fixed by the binary.
We never need to figure out `A` and `c` analytically — we can just **measure**
them, treating `verify_flag` as a black box.

The win condition is `out = ~T`, so we must solve the linear system:

```
A · flag = (~T) − c        (mod 256)
```

---

## 4. Exploitation

### 4.1 Measuring `A` and `c` with GDB

`verify_flag` writes its 64‑byte output to `[rsp]` right before the comparison
loop (at offset `0x1209` from the function/base). We drive GDB in batch mode:

1. Break at `verify_flag`, overwrite the 64 input bytes in memory with a chosen
   probe vector via `set *(char*)($rdi + i) = b`.
2. Break at `base + 0x1209` (right after `matvec` returns) and dump
   `x/64xb $rsp` — the raw output vector.

Because the map is affine:

* **Constant `c`:** feed the all‑zero vector → output is `c`.
* **Column `j` of `A`:** feed the unit vector `e_j` (1 in position `j`) →
  output is `A·e_j + c`, so column `j = output − c (mod 256)`.

That's `1 + 64 = 65` GDB runs to fully recover `A` and `c`.

```python
def query(flag_bytes):                  # run binary under gdb, return out[64]
    gdb: break verify_flag; patch rdi+i = b
         break *($base + 0x1209); x/64xb $rsp

b_const = query(bytes(64))              # c
for i in range(64):                     # columns of A
    e = bytearray(64); e[i] = 1
    col = (query(e) - b_const) % 256
```

### 4.2 Reading the target from the binary

The target `T` lives at file offset `0x32170`; the accept condition wants
`~T`:

```python
target     = data[0x32170:0x32170+64]
not_target = bytes(~b & 0xff for b in target)
```

### 4.3 Solving `A · flag = (~T) − c (mod 256)`

256 = 2⁸ is not a field, and `A` is generally singular mod 2, so we can't just
invert. The standard trick is **Hensel lifting** (2‑adic / bit‑by‑bit lifting):

1. Solve the system **mod 2** with Gaussian elimination over GF(2) — this fixes
   the lowest bit of every unknown.
2. Lift mod 2 → 4 → 8 → … → 256. At step `k`, compute the residual
   `r = (rhs − A·x) mod 2^{k+1}`, shift it down by `k`, and solve that
   reduced GF(2) system to obtain bit `k` of the solution.
3. After 8 lifts, `x mod 256` is the full solution = the flag.

```python
x = solve_mod2(M, rhs)                  # bit 0
for k in range(1, 8):                   # bits 1..7
    res   = [(rhs[i] - (A·x)[i]) % (1<<(k+1)) for i in range(64)]
    delta = solve_mod2(M, [r >> k for r in res])
    x     = [(x[j] + (delta[j] << k)) for j in range(64)]
flag = bytes(v % 256 for v in x)
```

### 4.4 Result

```
$ python3 exploit.py
[+] Flag: b'GPNCTF{juS7_ONe_0NstrUcTION5_Is_4LL_YoU_n3ED_MaY8e1239794fKfNdh}'

$ ./my-favorite-ingredient 'GPNCTF{juS7_ONe_0NstrUcTION5_Is_4LL_YoU_n3ED_MaY8e1239794fKfNdh}'
Correct flag!
```

---

## 5. Takeaways

* The SIMD obfuscation is cosmetic. Underneath the `vpmullw / vpand /
  vpackuswb / vpbroadcastd` noise, the checker is a plain **affine
  transformation over ℤ/256**: `out = A·flag + c`.
* Any affine/linear checker can be recovered as a black box by probing with the
  **zero vector** (constant term) and the **unit vectors** (matrix columns) —
  no need to reverse the math by hand.
* Solving linear systems mod a prime power (here 2⁸) is done with **Hensel /
  2‑adic lifting**: solve mod 2, then lift one bit at a time.