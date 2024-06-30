+++
title = "Summer School 2024"
date = 2024-07-01
+++

In the summer school conducted by the Cybersecuirty club, titled **"The Art of Exploitation"** , we provided a 9 session course on binary exploitation. 
This course coverd everythin from the basics of C to advanced topics including ret2libc, ASLR and more.

You can find the [YouTube playlist](https://www.youtube.com/watch?v=EfeU8pxDhVE&list=PLhHkiL2SJ7Xf9Meg6fj-yLJt1DJ0bwSAZ&pp=iAQB) of the recordings.
{{ youtube(id="videoseries?si=ycsHDJjAgbvuN5oM&amp;list=PLhHkiL2SJ7Xf9Meg6fj-yLJt1DJ0bwSAZ", class="textCenter") }}

The course had the following topics taught:

### Session 1
- Basic C language
- Basic Linux Commands

### Session 2
- Introduction to compilation
- Introduction to assembly language

### Session 3 
- Using GDB
- Overwriting a variable with basic buffer overflow

### Session 4
- Understanding how stack frames work
- Types of buffer overflow
- ret2function
- ret2shellcode

### Session 5
- Stack canaries as a mitigation to buffer overflow
- Leaking the canary with format string

### Session 6
- W^X, preventing shellcode execution
- ret2libc to overcome shellcode execution

### Session 7
- Understanding ASLR; the what, the how, and the why

### Session 8
- Position Independent Code
- Procedure Linkage Table
- Global Offset Table
- Relocations Read Only - and how it is a necessary evil

### Session 9
- Overcoming ASLR with ret2plt
- GOT overwrite with format string
