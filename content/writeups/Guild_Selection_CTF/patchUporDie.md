+++
title = 'Patch up or die'
date = '2024-09-05'
authors = ["Achintya J"]
+++



We've been given a binary, let's run that. So, we're getting a prompt to enter a number and when we do so, we get an error message. We keep getting that, nothing seems to be working. We also have `flag.txt` but it's not the actual flag of course, its encrypted. You can try and reverse the encryption, but there is an `easier way`.

We'll fire this up in IDA because it's the best disassembler ever!

You'll encounter this bit of code. At first it might seem harmless, but this code is essentially saying, that we move a random `time based` number into the `eax` register. This is what is used to compare out input to!

		.text:00401953                 lea     ecx, [esp+4]
		.text:00401957                 and     esp, 0FFFFFFF0h
		.text:0040195A                 push    dword ptr [ecx-4]
		.text:0040195D                 push    ebp
		.text:0040195E                 mov     ebp, esp
		.text:00401960                 push    esi
		.text:00401961                 push    ebx
		.text:00401962                 push    ecx
		.text:00401963                 sub     esp, 3Ch
		.text:00401966                 call    ___main
		.text:0040196B                 mov     dword ptr [esp], 0 ; Time
		.text:00401972                 call    _time
		.text:00401977                 mov     [esp], eax      ; Seed
		.text:0040197A                 call    _srand
		.text:0040197F                 call    _rand
		.text:00401984                 mov     [ebp+var_1C], eax

This means, there are 3 ways to move forward,

1. Reverse the flag encryption logic and decode it
2. Set a breakpoint when we load the random number and then use that
3. Patch the binary

Comparing all of these, I find it much easier to patch the logic. Here's how we do it,

		.text:00401987                 mov     dword ptr [esp+4], offset aEnterTheNumber ; "Enter the number: "
		.text:0040198F                 mov     dword ptr [esp], offset __ZSt4cout ; std::ostream::sentry *
		.text:00401996                 call    __ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
		.text:0040199B                 lea     eax, [ebp+var_28]
		.text:0040199E                 mov     [esp], eax
		.text:004019A1                 mov     ecx, offset __ZSt3cin ; std::cin
		.text:004019A6                 call    __ZNSirsERy     ; std::istream::operator>>(ulong long &)
		.text:004019AB                 sub     esp, 4
		.text:004019AE                 mov     eax, [ebp+var_1C]
		.text:004019B1                 mov     edx, 0
		.text:004019B6                 mov     [ebp+var_30], eax
		.text:004019B9                 mov     [ebp+var_2C], edx
		.text:004019BC                 mov     eax, [ebp+var_28]
		.text:004019BF                 mov     edx, [ebp+var_24]
		.text:004019C2                 mov     ecx, [ebp+var_30]
		.text:004019C5                 xor     ecx, eax
		.text:004019C7                 mov     ebx, ecx
		.text:004019C9                 mov     ecx, [ebp+var_2C]
		.text:004019CC                 xor     ecx, edx
		.text:004019CE                 mov     esi, ecx
		.text:004019D0                 mov     eax, esi
		.text:004019D2                 or      eax, ebx
		.text:004019D4                 test    eax, eax
		.text:004019D6                 jnz     short loc_4019DF
		.text:004019D8                 call    __Z22decrypt_and_print_flagv ; decrypt_and_print_flag(void)
		.text:004019DD                 jmp     short loc_401A06

This is the main function. Look at this specific code here,

		.text:004019D4                 test    eax, eax
		.text:004019D6                 jnz     short loc_4019DF

This is being used to compare the two values (the one we enter and the random number), and if it's not true, then we jump to the error message code. So, if we patch the binary by changing these instructions to `nop`.

We change the first first 4 bytes to 90 in the `test` instruction. `90` stands for the `nop` instruction, which is the instruction which will be skipped over. Hence, we can control the flow of execution through this.

		.text:004019D4                 nop  
		.text:004019D6                 nop  

Thus, we are going to call the `decrypt_and_print_flag()` regardless of whether the number we enter is same as the random time based number. 

flag: `IITMCTF{B1n4ry_p4tch1ng_r0ck5}`
