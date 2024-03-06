#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define XOR_CIPHER 'X'

int main(int argc, char *argv[]) {
    char *mapped_memory;
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_binary>\n", argv[0]);
        return 1;
    }

    // Open the binary file
    int fd = open(argv[1], O_RDWR);
    if (fd == -1) {
        perror("Failed to open the binary file");
        return 1;
    }

    // Get the size of the file
    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1) {
        perror("Failed to get the file size");
        close(fd);
        return 1;
    }

    // Map the file to memory
    mapped_memory = mmap(NULL, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped_memory == MAP_FAILED) {
        perror("Failed to map the file to memory");
        close(fd);
        return 1;
    }

    // Encrypt the data in memory
    unsigned char *ptr = (unsigned char *)mapped_memory;
    for (off_t i = 0; i < file_stat.st_size; ++i) {
        ptr[i] ^= XOR_CIPHER;
    }

    // Unmap the memory
    if (munmap(mapped_memory, file_stat.st_size) == -1) {
        perror("Failed to unmap the file from memory");
        close(fd);
        return 1;
    }

    // Close the file
    close(fd);

    // Execute the modified binary
    if (execv(argv[1], argv + 1) == -1) {
        perror("Error executing the file");
        return 1;
    }

    return 0;
}