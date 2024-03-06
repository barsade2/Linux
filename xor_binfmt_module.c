#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/memfd.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/elf.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/syscalls.h>

#define ELF_MAGIC_BYTES "\x7f\x45\x4c\x46"
#define ELF_MAGIC_SIZE 4
#define XOR_CIPHER 'X'

static int load_xor_encrypted_elf(struct linux_binprm* bprm);
static int do_load_xor_encrypted_elf(struct linux_binprm* bprm);
static void decrypt_mapped_memory(char *shared_mem, size_t shared_mem_size);
static int verify_elf_headers(struct linux_binprm *bprm);
static int init_xor_encrypted_elf_loader(void);
static void exit_xor_encrypted_elf_loader(void);

int load_xor_encrypted_elf(struct linux_binprm* bprm) {
    return do_load_xor_encrypted_elf(bprm);
}

int do_load_xor_encrypted_elf(struct linux_binprm* bprm) {
    char *mapped_memory;
    loff_t mapped_memory_size = bprm->file->f_inode->i_size;

    // Verify the magic bytes to ensure it's an ELF encrypted with XOR
    int ret = verify_elf_headers(bprm);
    if (ret != 0) {
        return -ENOEXEC;
    }

    // Create an in-memory file
    int fd = syscall(SYS_memfd_create, "anonymous_elf", MFD_ALLOW_SEALING);
    if (fd == -1) {
        printk(KERN_ERR "Failed to create in-memory file\n");
        return -ENOEXEC;
    }

    // Resize the in-memory file
    int truncate = ksys_ftruncate(fd, mapped_memory_size);
    if (truncate == -1) {
        printk(KERN_ERR "Failed to resize the in-memory file\n");
        ksys_close(fd);
        return -ENOEXEC;
    }

    // Map the in-memory file to memory
    mapped_memory = ksys_mmap_pgoff(NULL, mapped_memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);    
    if (mapped_memory == MAP_FAILED) {
        printk(KERN_ERR "Failed to map the file to memory\n");
        ksys_close(fd);
        return -ENOEXEC;
    }

    // Read the encrypted content from the original file to memory
    if (ksys_read(fd, mapped_memory, mapped_memory_size)) {
        printk(KERN_ERR "Failed to read file content\n");
        vm_munmap(mapped_memory, mapped_memory_size);
        ksys_close(fd);
        return -ENOEXEC;
    }
    ksys_lseek(fd, 0, SEEK_SET);

    // Decrypt the shared memory content
    decrypt_mapped_memory(mapped_memory, mapped_memory_size);

    // Write the decrypted content back to the original file
    int write = kernel_write(bprm->file, mapped_memory, mapped_memory_size, 0);
    if (write != mapped_memory_size) {
        printk(KERN_ERR "Failed to write decrypted content to file\n");
        vm_munmap(mapped_memory, mapped_memory_size);
        ksys_close(fd);
        return -EIO;
    }

    // By now the executable is decrypted and is a valid ELF, call ELF loader.
    // Only the content of the bprm->file was changed (and not its size, memory address, etc)
    // resulting with keeping the integrity of the linux_binprm struct.
    return load_elf_binary(bprm);
}

void decrypt_mapped_memory(char *shared_mem, size_t shared_mem_size) {
    size_t i;
    for (i = 0; i < shared_mem_size; ++i) {
        shared_mem[i] ^= XOR_CIPHER;
    }
}

int verify_elf_headers(struct linux_binprm *bprm) {
    char buf[ELF_MAGIC_SIZE];
    ssize_t ret = vfs_read(bprm->file, buf, ELF_MAGIC_SIZE, 0);
    if (ret < 0) {
        printk(KERN_ERR "Error reading from file\n");
        return ret;
    }

    for (int i = 0; i < 4; ++i) {
        buf[i] ^= XOR_CIPHER;
    }

    if (memcmp(buf, ELF_MAGIC_BYTES, ELF_MAGIC_SIZE) != 0) {
        printk(KERN_ERR "Magic numbers do not match\n");
        return -ENOEXEC;
    }

    printk(KERN_INFO "Magic numbers match\n");
    return 0;
}

static struct linux_binfmt xor_encrypted_elf_format = {
    .module = THIS_MODULE,
    .load_binary = load_xor_encrypted_elf,
};

static int init_xor_encrypted_elf_loader(void) {
    register_binfmt(&xor_encrypted_elf_format);
}

static void exit_xor_encrypted_elf_loader(void) {
    unregister_binfmt(&xor_encrypted_elf_format);
}

module_init(init_xor_encrypted_elf_loader);
module_exit(exit_xor_encrypted_elf_loader);
