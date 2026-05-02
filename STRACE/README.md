# minimal_strace

A minimal `strace` clone using `ptrace`.

## What it does

Traces all syscalls made by a target program and prints for each one:
- Syscall name and number
- All 6 argument registers (rdi, rsi, rdx, r10, r8, r9)
- Return value
- Elapsed time in microseconds

## How it works

Forks a child process, which calls `PTRACE_TRACEME` then `execvp` to load the target. The parent uses `PTRACE_SYSCALL` to stop the child at every syscall entry and exit. At entry, `rax == -ENOSYS`, so the syscall number is read from `orig_rax`. At exit, `rax` holds the return value.

Timing is done with `clock_gettime(CLOCK_MONOTONIC)` between entry and exit stops.

## Dependencies

- None (uses kernel ptrace interface directly)

## Compilation

```bash
gcc -Wall minimal_strace.c -o min_strace
```

## Usage

```bash
./min_strace <program> [args...]
```

Example:
```bash
./min_strace ./minimal_strace_test
```

## Test program

`minimal_strace_test.c` prints its own PID via `fprintf`, which triggers a small set of syscalls (write, getpid, etc.).

## Notes

- x86-64 Linux only.
- Syscall table covers entries 0–334.
- `exit_group` (231) is handled as a special case since there is no syscall exit stop for it.
