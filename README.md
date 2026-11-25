# House of Muney

House of Muney uses an oversized `mmap`-backed malloc chunk to unmap libc's
read-only symbol-lookup data, then reclaims the same virtual addresses as
writable memory. The technique and the original glibc 2.31 demonstration are
documented in the [research article](https://4xura.com/binex/heap/house-of-muney/).
This repository also contains working adaptations for glibc 2.38 and 2.43.

## Exploit path

After page-alignment checks, glibc derives an mmapped chunk's unmap range from
its recorded metadata. A forged size can make `free()` unmap more than the
original allocation. A subsequent `malloc()` can occupy the released range,
including addresses where libc's `.gnu.hash` and `.dynsym` had been mapped
read-only.

```text
                         higher virtual addresses
        +--------------------------------------------------+
        | libc .gnu.hash / .dynsym                 [r--]    |<--+
        +--------------------------------------------------+   |
        | startup-thread TLS (thread has exited)  [rw-]    |   | forged
        +--------------------------------------------------+   | chunk size
        | mmap victim chunk                       [rw-]    |---+
        +--------------------------------------------------+
        | worker TLS and stack (remain mapped)    [rw-]    |
        +--------------------------------------------------+
                         lower virtual addresses

        forged free()
             |
             v
        munmap() through libc's lookup pages
             |
             v
        malloc() reclaims the hole as writable memory
             |
             v
        restore lookup data; change GNU hash + dynsym
             |
             v
        dlsym("getenv") -> system address -> call("/bin/sh")
```

The glibc 2.38 and 2.43 builds tested here place the startup thread's TLS in
the anonymous pages immediately below libc. Unmapping those pages from that
same thread prevents it from continuing. The modern PoCs allocate the victim
first, start a worker whose TLS is below it, and let the startup thread exit.
The worker performs the forged `free()` and replacement `malloc()`.
Both programs fix the mmap threshold at `0x20000` so that replacement stays
mmap-backed after the forged free.

The replacement mapping is populated with a saved copy of libc's first
`0x1c000` bytes.
The PoCs then edit the GNU-hash Bloom word, bucket and chain for `getenv`, and
change its `.dynsym` value to the offset of `system`. The modern binaries use
Full RELRO: their PLT entries are resolved at startup, so execution reaches
the modified metadata through a **fresh `dlsym` lookup** instead of a lazy PLT
call. The 2.43 build also accounts for the 16-byte difference in its mmapped
chunk-size bookkeeping relative to the tested 2.38 build.

## PoCs and runtimes

| Source | Tested libc | Resolution trigger | libc build ID |
| --- | --- | --- | --- |
| [glibc 2.31](PoC/house_of_muney_glibc-2.31.c) | Ubuntu 20.04 `2.31-0ubuntu9.9` | Lazy `exit@plt` | See source |
| [glibc 2.38](PoC/house_of_muney_glibc-2.38.c) | Fedora 39 glibc 2.38 | Fresh `dlsym` under Full RELRO | `1cd2d1016ef987f11f5709c2aa0deb4520dcc851` |
| [glibc 2.43](PoC/house_of_muney_glibc-2.43.c) | Kali 2026.2 `2.43-4` | Fresh `dlsym` under Full RELRO | `9bee4eb8329d9d71d9f59a08465751cbc1a1f7cf` |

The repository contains the PoC sources, not the libc or loader binaries.
The offsets in each file belong to its listed libc build. Use a matching
`libc.so.6` and `ld-linux-x86-64.so.2` pair; a version number alone does not
establish matching symbol-table offsets. Check a candidate library with
`readelf -n libc.so.6` for its build ID, then use `readelf -W -S` and
`readelf -W -s` to recalculate its `.gnu.hash`, `.dynsym` and function offsets
before adapting a PoC.

## Reproduce

Build on Kali 2026.2 with the listed glibc 2.43 build:

```sh
gcc -O0 -Wall -Wextra -Werror -fPIE -pie -pthread \
  -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack \
  -o /tmp/house_of_muney_glibc-2.43 PoC/house_of_muney_glibc-2.43.c
printf 'echo MUNEY_SHELL_OK\nexit\n' | /tmp/house_of_muney_glibc-2.43
```

For glibc 2.38, build the corresponding source and invoke it with the
matching Fedora 39 loader and library directory:

```sh
gcc -O0 -Wall -Wextra -Werror -fPIE -pie -pthread \
  -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack \
  -o /tmp/house_of_muney_glibc-2.38 PoC/house_of_muney_glibc-2.38.c
GLIBC238_DIR=/path/to/matching-fedora-39-libraries
printf 'echo MUNEY_SHELL_OK\nexit\n' | \
  "$GLIBC238_DIR/ld-linux-x86-64.so.2" \
  --library-path "$GLIBC238_DIR" /tmp/house_of_muney_glibc-2.38
```

Successful runs show the forged `free()` returning, the replacement allocation
at the expected address, `dlsym("getenv")` resolving to `system`, and
`MUNEY_SHELL_OK` from the shell. `checksec` reports Full RELRO, canary, NX and
PIE for both modern binaries. Each passed 20/20 fresh-process runs on its
listed runtime.

## Scope of the demonstrations

These are allocator and dynamic-linker mechanism PoCs. They write the victim
chunk's size directly, use `dladdr` to establish libc's base, and save libc's
lookup data before unmapping it. Those steps are instrumentation in the PoCs;
an exploit against a separate program needs reachable primitives for them.
