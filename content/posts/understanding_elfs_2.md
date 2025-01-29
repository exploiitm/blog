+++
title = "Understanding ELFs, part 2"
date = 2025-01-29
authors = ["InnocentZero"]
+++

## Segments

Sections gather all the information needed to link a given executable. Segments, on the other
hand, contain information needed to load the program into memory. Segments can be imagined as
a tool to make linux loader's life easier, as they group sections by attributes into single
segments in order to make the loading process more efficient. Otherwise the loader would load
each individual section into memory independently.

Similar to sections, Segments, also called _Program Headers_, also have a **Program Header Table**
that lists all the segments. This table is read by the loader and helps map the ELF into memory.
These can be seen via `readelf -l executable`.

```
Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1040
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000630 0x0000000000000630  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000191 0x0000000000000191  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x00000000000000bc 0x00000000000000bc  R      0x1000
  LOAD           0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0
                 0x0000000000000248 0x0000000000000250  RW     0x1000
  DYNAMIC        0x0000000000002de0 0x0000000000003de0 0x0000000000003de0
                 0x00000000000001e0 0x00000000000001e0  RW     0x8
  NOTE           0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000040 0x0000000000000040  R      0x8
  NOTE           0x0000000000000378 0x0000000000000378 0x0000000000000378
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_PROPERTY   0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000040 0x0000000000000040  R      0x8
  GNU_EH_FRAME   0x0000000000002018 0x0000000000002018 0x0000000000002018
                 0x0000000000000024 0x0000000000000024  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0
                 0x0000000000000230 0x0000000000000230  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame 
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss 
   06     .dynamic 
   07     .note.gnu.property 
   08     .note.gnu.build-id .note.ABI-tag 
   09     .note.gnu.property 
   10     .eh_frame_hdr 
   11     
   12     .init_array .fini_array .dynamic .got 
```

## Types of Segments

There are many types of segments. The most common and important ones are:

- `PT_PHDR`: Contains the program header.
- `PT_LOAD`: Actually loaded in the memory. Every other section is mapped to this.
- `PT_INTERP`: Holds the `.interp` section responsible for providing the interpreter.
- `PT_NULL`: First entry of the table, unassigned.
- `PT_DYNAMIC`: Holds the `.dynamic` section.


An interesting thing to note here is the `GNU_STACK` segment in the output. It has a peculiar
size of 0. This implies that the stack size is decided by the kernel. Its size is always
ignored and it is just there for permission management.

Another thing to be mentioned is `GNU_EH_FRAME` that specifies the frame unwinding information.
Usually the same as `.eh_frame_hdr` section.
