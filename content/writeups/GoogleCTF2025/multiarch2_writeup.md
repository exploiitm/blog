+++
title = "MultiArch2"
date = "2025-09-03"
authors = ["Vrishab"]
+++
## Summary of the Exploit

This challenge is built around exploiting a custom VM built with two separate instruction sets (stack‑based and register‑based)

Inside the register‑based instruction set, a key bug in the XOR instruction lets us write outside the space reserved for registers. This allows us to trick the VM so that a normal VM memory address (`0xA000`) actually points to the VM’s own internal state struct `masm_struct`. We can leak useful memory addresses from inside the VM, overwrite the VM function pointer `get_flag` to make it point to our shellcode and thereafter trigger that function pointer and get code execution

---

## VM Setup

When the VM runs, it loads a custom file format called `.masm`, each of which consists of several regions that get mapped when the VM starts:
- **Code segment**: the instructions the VM runs
- **Data segment**: attacker‑controlled, marked as rwx i.e. read, write, execute
- **Stack segment**: where stack‑arch instructions operate
- **Arch table**: tells the VM about whether each instruction runs in stack mode or register mode

This design means we can place custom shellcode directly into the data segment, then aim to transfer execution there

---

### VM State: `masm_struct`
Internally, the VM maintains everything in a large structure `masm_struct`. It contains:
- pointers to the code, data, and arch table in memory
- four general registers, a stack pointer, and program counter
- function pointer called **`get_flag`** at offset `0x28`, which we want to hijack
- metadata about heap allocations (`heap_array`)

---

## Vulnerability: Out‑of‑Bounds XOR

Inside the register instruction set, there is an instruction 
```0x41 <idx> <imm32>` is supposed to do `registers[idx] ^= imm32```

The issue is that the VM never checks whether  `idx`  is a valid register index. By giving a large enough index, we can XOR into memory well beyond the register array, which overlaps with the  `heap_array`. By crafting values, we can change one of the heap metadata pointers stored there

---

## Exploit

### Step 1 – Making Heap Allocation
Using stack‑arch syscall `6`, we allocate a heap block. The VM maps it at virtual address `0xA000`, and internally records the mapping in `heap_array[0]` - `{ real_heap_ptr, 0xA000 }`

---

### Step 2 – Corrupting Heap Metadata
We switch to register‑arch and use the buggy XOR on a big index so we land inside and overwrite `heap_array.real_ptr`. Instead of pointing to the real heap, we flip it so it points to the `masm_struct` itself. So now whenever we use `0xA000`, we are actually accessing the VM’s internal state struct

---

### Step 3 – Leaking Information
We use stack‑arch syscall 2 (fwrite) to dump memory starting from `0xA000`. But `0xA000` maps `masm_struct`, so this gives us a leak of critical VM internals i.e. the real memory address of the **data segment** (`seg1`), which we control. This is the RWX memory where shellcode is already stored

---

### Step 4 – Overwriting the get_flag Pointer
We now use register‑arch syscall 1 (fread) to write into VM memory (at `0xA000 + 0x28`, which resolves to `&masm_struct->get_flag` due to our corruption). We overwrite that with the leaked `seg1` address. Now whenever the VM tries to call `get_flag`, it will instead jump to our data segment where we've placed our shellcode

---

### Step 5 – Running Shellcode
Finally, we use stack‑arch syscall 5, which usually calls `get_flag`. But it now points to our RWX data segment, so the syscall runs our injected shellcode

---

## Overall Exploit Flow
1. Allocate heap chunk at `0xA000`
2. Use buggy XOR to poison heap_array so `0xA000` maps to `masm_struct`
3. Dump (`fwrite`) `masm_struct` and find seg1 address
4. Overwrite `get_flag` with that address
5. Call `syscall 5` → shellcode runs


**Credits**: 堇姬 Naup (https://naup.mygo.tw/2025/07/05/2025-Google-CTF-writeup/)
