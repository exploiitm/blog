+++
title = "Understanding ELFs, part 1"
date = 2025-01-08
authors = ["InnocentZero"]
+++

In this post we analyze the header and sections of an ELF binary on disk.

## The header

ELF files have a header section that can be read with `readelf -h executable` which gives you quite
a bit of information about the binary.

```
ELF Header:
Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
Class:                             ELF64
Data:                              2's complement, little endian
Version:                           1 (current)
OS/ABI:                            UNIX - System V
ABI Version:                       0
Type:                              DYN (Position-Independent Executable file)
Machine:                           Advanced Micro Devices X86-64
Version:                           0x1
Entry point address:               0x1040
Start of program headers:          64 (bytes into file)
Start of section headers:          13520 (bytes into file)
Flags:                             0x0
Size of this header:               64 (bytes)
Size of program headers:           56 (bytes)
Number of program headers:         13
Size of section headers:           64 (bytes)
Number of section headers:         30
Section header string table index: 29
```

Needless to say, a lot of this is just metadata about the binary that is read by the OS to load
the binary.

## The sections
ELF sections comprise all all the information that is needed to build an executable from an
object file. They are only needed during compile time and not runtime. However, some of these
sections may get mapped to segments during runtime. `readelf -S executable` tells you the
sections.

Some of the more important ones are:

- `.text`: The instructions of the binary are contained here. They are executed and `rip` moves
  through this section.
- `.data/.rodata`: This are the sections that contain initialized global data. _ro_ stands for
  read-only.
- `.bss`: This is the section for uninitialized global variables.
- `.interp`: This holds the runtime linker, also known as the /interpreter/ of the program.
- Some linker scripts may also contain preallocated space for stack and heap, although it's not
  really the job of ELF sections to define them.

For an example /hello world/ binary in C, the following was the output for `readelf -S`

```
  There are 30 section headers, starting at offset 0x34d0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000000318  00000318
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.pr[...] NOTE             0000000000000338  00000338
       0000000000000040  0000000000000000   A       0     0     8
  [ 3] .note.gnu.bu[...] NOTE             0000000000000378  00000378
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .note.ABI-tag     NOTE             000000000000039c  0000039c
       0000000000000020  0000000000000000   A       0     0     4
  [ 5] .gnu.hash         GNU_HASH         00000000000003c0  000003c0
       000000000000001c  0000000000000000   A       6     0     8
  [ 6] .dynsym           DYNSYM           00000000000003e0  000003e0
       00000000000000a8  0000000000000018   A       7     1     8
  [ 7] .dynstr           STRTAB           0000000000000488  00000488
       000000000000008f  0000000000000000   A       0     0     1
  [ 8] .gnu.version      VERSYM           0000000000000518  00000518
       000000000000000e  0000000000000002   A       6     0     2
  [ 9] .gnu.version_r    VERNEED          0000000000000528  00000528
       0000000000000030  0000000000000000   A       7     1     8
  [10] .rela.dyn         RELA             0000000000000558  00000558
       00000000000000c0  0000000000000018   A       6     0     8
  [11] .rela.plt         RELA             0000000000000618  00000618
       0000000000000018  0000000000000018  AI       6    23     8
  [12] .init             PROGBITS         0000000000001000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [13] .plt              PROGBITS         0000000000001020  00001020
       0000000000000020  0000000000000010  AX       0     0     16
  [14] .text             PROGBITS         0000000000001040  00001040
       0000000000000141  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         0000000000001184  00001184
       000000000000000d  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         0000000000002000  00002000
       0000000000000015  0000000000000000   A       0     0     4
  [17] .eh_frame_hdr     PROGBITS         0000000000002018  00002018
       0000000000000024  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         0000000000002040  00002040
       000000000000007c  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000003dd0  00002dd0
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000003dd8  00002dd8
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .dynamic          DYNAMIC          0000000000003de0  00002de0
       00000000000001e0  0000000000000010  WA       7     0     8
  [22] .got              PROGBITS         0000000000003fc0  00002fc0
       0000000000000028  0000000000000008  WA       0     0     8
  [23] .got.plt          PROGBITS         0000000000003fe8  00002fe8
       0000000000000020  0000000000000008  WA       0     0     8
  [24] .data             PROGBITS         0000000000004008  00003008
       0000000000000010  0000000000000000  WA       0     0     8
  [25] .bss              NOBITS           0000000000004018  00003018
       0000000000000008  0000000000000000  WA       0     0     1
  [26] .comment          PROGBITS         0000000000000000  00003018
       0000000000000036  0000000000000001  MS       0     0     1
  [27] .symtab           SYMTAB           0000000000000000  00003050
       0000000000000240  0000000000000018          28     6     8
  [28] .strtab           STRTAB           0000000000000000  00003290
       000000000000012a  0000000000000000           0     0     1
  [29] .shstrtab         STRTAB           0000000000000000  000033ba
       0000000000000116  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```


- `Nr`, `Name`, and `Size` should be obvious.
- `EntSize` contains the size of the entries, if the entries in the section have fixed sizes. Like
  symbol tables.
- `Type` will be explained later. `Address` contains the starting address of the section in the
  binary. This depends on the previous sections and the alignment requirements of the section.
- `Offset` and `Align` should also be obvious. The fields below `Address` will be explained below.

The types of sections:

- `NULL`: This marks an empty section. It is the first section of the binary for demarcation
  purposes. Acts as a placeholder.
- `PROGBITS`: These just have program-defined info, like the instructions (`.text`), the global
  data (`.data/.rodata`), the `.interp` section (defines the interpreter).
- `DYNAMIC`: Holds dynamic linking information. It is actually a dynamic table that has tags
  and name/value mapping of sorts that helps the runtime linker load shared libs and stuff.
- `INIT_ARRAY`: This contains an array of pointers to functions that must be executed before
  `main`. Only for `.init_array`.
- `FINI_ARRAY`: This contains an array of pointers to functions that must be executed on `exit`.
  Only for `.fini_array`.
- `GNU_HASH`: This is a sort of hash table for faster symbol lookup used by the dynamic linker.
  Used for `.gnu.hash`
- `NOBITS`: Used for `.bss`, which is *zeroed out* upon loading. This contains the section having
  undefined global variables.
- `DYNSYM`: Used for `.dynsym` section, contains the dynamic symbol table.
- `STRTAB`: As the name suggests, it contains a string table. Usually it's indexed. For sections
  `.strtab` and `.dynstr`, which are obviously static and dynamic string tables.
- `SYMTAB`: Once again, symbol table for `.symtab`. Larger than `.dynsym` as it's more detailed, but
  not required at runtime.
- `RELA`: Contains reloc tables. These specify how to to modify certain addresses in the program
  to account for the layout of shared libraries or changes in addresses during linking.

I'm not covering specific sections like `.got` and `.plt` in detail as they require a separate post
of their own.

The flags for each section have been added below in the `readelf` output. 

The link section is an index to another section to indicate a dependency.

The info section is an index to another section to indicate additional
information.
