# House of Muney

Local PoCs for the mmap-chunk overlap and dynamic-linker symbol-resolution
technique described in the [House of Muney writeup](https://4xura.com/binex/heap/house-of-muney/).

| PoC | Tested runtime | libc build ID |
| --- | --- | --- |
| [glibc 2.31](PoC/house_of_muney_glibc-2.31.c) | Ubuntu 20.04, `2.31-0ubuntu9.9` | See source |
| [glibc 2.38](PoC/house_of_muney_glibc-2.38.c) | Fedora 39, glibc 2.38 | `1cd2d1016ef987f11f5709c2aa0deb4520dcc851` |
| [glibc 2.43](PoC/house_of_muney_glibc-2.43.c) | Kali 2026.2, `2.43-4` | `9bee4eb8329d9d71d9f59a08465751cbc1a1f7cf` |

The new PoCs use offsets for **these exact libc builds**. Keep the loader and
libc from the same installation. Check another build's `.gnu.hash`, `.dynsym`,
and symbol offsets with `readelf` before adapting either file.

## Build and run

On Kali with the listed glibc 2.43 build:

```sh
gcc -O0 -Wall -Wextra -Werror -fPIE -pie -pthread \
  -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack \
  -o /tmp/house_of_muney_glibc-2.43 PoC/house_of_muney_glibc-2.43.c
printf 'echo MUNEY_SHELL_OK\nexit\n' | /tmp/house_of_muney_glibc-2.43
```

For glibc 2.38, compile the 2.38 source with the same flags, then run it with
the matching Fedora 39 loader and libc directory:

```sh
gcc -O0 -Wall -Wextra -Werror -fPIE -pie -pthread \
  -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack \
  -o /tmp/house_of_muney_glibc-2.38 PoC/house_of_muney_glibc-2.38.c
LD238=/path/to/ld-linux-x86-64.so.2
LIB238_DIR=/path/to/matching-libc-directory
printf 'echo MUNEY_SHELL_OK\nexit\n' | \
  "$LD238" --library-path "$LIB238_DIR" /tmp/house_of_muney_glibc-2.38
```

Both runs should show the forged `free` returning, a replacement `malloc` at
the original address, GNU hash table edits, a `dlsym` result equal to
`system`, and `MUNEY_SHELL_OK` from the spawned shell. `checksec` on either
compiled binary should report Full RELRO, canary, NX and PIE.
Both version-specific PoCs passed 20/20 fresh process runs with those
protections enabled on their listed runtimes.

## Why the new path uses a worker

On these runtimes the three anonymous pages immediately below libc hold the
main thread's TLS. A forged `free` that reaches libc unmaps those pages too,
so the original single-thread path crashes. Each modern PoC allocates the
victim first, starts a worker with TLS below it, and exits the main thread.
The worker enlarges and frees the victim, reclaims the hole, restores libc's
lookup metadata, then explicitly forges the GNU hash bloom word, bucket and
chain entry. Finally it changes `getenv`'s `.dynsym` value to `system`, makes
a fresh `dlsym(RTLD_DEFAULT, "getenv")` lookup, and calls the returned address
with `/bin/sh`. Full RELRO resolves the executable's PLT at startup, but a
later `dlsym` still consults libc's GNU hash and dynamic symbol table.

These programs are mechanism demonstrations. Their direct size overwrite,
saved copy of libc metadata, and `dladdr` lookup are instrumentation; a pwn
challenge needs attacker-reachable primitives for those stages.

