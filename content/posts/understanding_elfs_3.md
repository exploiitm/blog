+
title = "Understanding ELFs, part 3"
date = 2025-01-30
authors = ["InnocentZero"]
+++

## On relocations, loading binaries, and more

The reason we need relocations is because of a simple fact, the existence of shared libraries.

One question anyone may ask is the necessity of having shared libraries. That is done to avoid
repitition of pages in memory, a thing which was critical in older days because of low memory. 
Another thing to note is that there is separation of the library and the binary. The library can
be updated without updating the binary as such.

This is dealt with by using _relocation sections_. These contain the info needed to do the
relocation of the symbol within the binary's context. The section usually links to an additional
section where the relocation is going to happen.

There are two ways in which object files may be linked: statically and dynamically.

Static linking is fairly straightforward, the linker takes in all the object files and archive
files (=libc.a=) and creates a single self-contained binary containing all the required
functionality. This is done at the end of compilation itself.

Dynamic linking is a slightly more complex and involved process. It defers the linking part from
compile time to runtime. The binary contains the information about its choice of runtime linker
(also referred to as an _interpreter_) and the dynamic symbols and how to obtain them.


## Loading an ELF on the memory

The system first executes the file's "interpreter" before handing over execution to the binary.
Over here, the interpreter is obtained from the `.interp` section in the `PT_INTERP` segment in
memory. This can be read using `readelf -p .interp example`.

```
$ readelf -p .interp example

String dump of section '.interp':
  [     0]  /lib64/ld-linux-x86-64.so.2
```

The interpreter loads the binary into memory first.

The interpreter sets up the environment using the `.dynamic` section of the binary. This can be
seen using `readelf -d executable`.

In this, the interpreter will recursively begin visiting all the **NEEDED** dynamic libraries to be
loaded into memory. For each dependency, the following steps are executed:

- The ELF is mapped into memory.
- Relocations are performed, in the original binary we patch all the absolute addresses and
  resolve references to other object files.
- Its dynamic table is parsed and dependencies loaded.
- Run `dl_init`, which executes all the functions from `INIT`, and `INIT_ARRAY` for the just loaded
  libraries.

Now the control is handed over to `_start` in the ELF binary. That gets the pointer to `_dl_fini`
in `rdx`. This prepares the stack with a few arguments and calls `_libc_start_main`.

`_libc_start_main` receives a function pointer to `main`, `init`, `fini`, and `rtld_fini` (this is the
same as `dl_fini`).

This function has a bunch of things going on, such as setting up of thread local storage and
such. Here we only care about two things:

- `__cxa_atexit__` which sets up `_dl_fini` as the destructor after the program is done.

- A call to `call_init` that run the constructors in the `INIT` and `INIT_ARRAY` dynamic table
  entries. Note that `dl_init` was for the entries in the shared libraries themselves, but this
  is for the binary.
  
- Finally, control after this is handed over to `main`.

- Immediately after `main`, `exit` is called. This only transfers the control to
  `__run_exit_handlers`.

- This runs all the functions registered in `__exit_funcs` which also contains `_dl_fini`.
