# minimal_file_lelf

A minimal clone of the `file` command for ELF binaries, built with libelf.

## What it does

Parses an ELF binary and prints:
- Architecture (x86, x86-64, ARM, RISC-V, etc.)
- Class (32-bit / 64-bit)
- Endianness
- OS/ABI
- Entry point address
- File type (executable, shared library, relocatable, core)
- Section table with name, type, address, offset, and size
- Symbol table (functions and objects with address and name)

## Dependencies

- libelf (`-lelf`)

## Compilation

```bash
gcc -Wall -Werror minimal_file_lelf.c -o elfloader -lelf
```

## Usage

```bash
./elfloader <elf_binary>
```

Example:
```bash
./elfloader /bin/ls
```

## Test binary

`minimal_file_lelf_test.c` is a simple two-function program (foo + main) to use as a target:

```bash
gcc -g minimal_file_lelf_test.c -o test_elf
./elfloader test_elf
```

## Notes

- Requires the binary to have a `.symtab` section (non-stripped).
- Dies with an error message if `.symtab` is not found.
