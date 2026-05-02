# mdb — Minimal Debugger

A minimal GDB-style debugger for 64-bit no-PIE ELF executables, built with ptrace, libelf, and Capstone.

## What it does

- Set breakpoints by symbol name or address
- List and delete breakpoints
- Run the target with optional arguments or input redirection
- Continue execution
- Single-step one instruction at a time
- Disassemble 10 instructions from the current PC

## Commands

| Command         | Description                                              |
|----------------|----------------------------------------------------------|
| `b <symbol>`   | Set breakpoint at symbol                                 |
| `b *<address>` | Set breakpoint at address                                |
| `l`            | List all breakpoints                                     |
| `d <num>`      | Delete breakpoint by number                              |
| `r [args]`     | Run the program (supports `< file` for stdin redirect)   |
| `c`            | Continue execution                                       |
| `si`           | Step one instruction                                     |
| `disas`        | Disassemble 10 instructions from current PC              |
| `q`            | Quit, kill tracee, and free memory                       |

## How it works

Loads the target ELF with libelf to extract `.symtab` (static symbols) and `.plt` entries from `.rela.plt` + `.dynsym` (dynamic symbols). Breakpoints are set by writing `0xCC` (INT3) over the first byte of the target address with `PTRACE_POKEDATA`, saving the original byte. On hit, the original byte is restored, RIP is decremented by 1, and the breakpoint is re-armed after the next step.

Symbols not yet resolved at breakpoint-set time (e.g. set before `r`) are marked pending and resolved when the program starts.

Disassembly reads memory from the tracee with `PTRACE_PEEKDATA` and passes it to Capstone (AT&T syntax).

## Dependencies

- libelf (`-lelf`)
- Capstone (`-lcapstone`)

## Compilation

```bash
gcc -Wall minimal_gdb.c -o mdb -lelf -lcapstone
```

## Usage

```bash
./mdb <elf_binary>
```

Example:
```bash
./mdb ./minimal_gdb_test
(mdb) b foo
(mdb) r
(mdb) si
(mdb) c
(mdb) q
```

## Test binary

`minmal_gdb_test.c` has a `foo` function called from `main`, suitable for testing breakpoints and single-stepping.

```bash
gcc -g -no-pie minmal_gdb_test.c -o gdb_test
./mdb gdb_test
```

## Notes

- Targets must be non-PIE (`-no-pie`) 64-bit ELF executables.
- Stripped binaries are supported but symbol-based breakpoints won't resolve.
