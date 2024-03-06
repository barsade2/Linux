# Linux

There are 2 solutions for the assignment, involving implementing 2 different mechanism types.

**Kernel Module (xor_binfmt_module.c + encrypt_and_execute.c):**

I created a kernel module that provides a custom binary format that receives a XOR encrypted ELF.
The module is registered in the kernel and then added to the registered binary formats list.


When the search_binary_handler() invokes my binary format, the module decrypts the 4 first bytes (magic bytes)
with the constant key, and checks if they are equal to ELF magic numbers (\x7f\x45\x4c\x46).


Once they do, the module creates an anonymous file and reads all the data from bprm->file to the anonymous file.
The decryption process occurs in-memory (and reflects the changes directly to the anonymous file by declaring 
'MAP_SHARED' when mapping it to memory).


Next step includes writing all the decrypted data into the original file, resulting in turning this file to a valid
ELF file. Since it is now a valid ELF file, final steps directly invokes the load_elf_binary() of the ELF loader.

**Binfmt_misc Handler (binfmt_misc_decryptor):**

Another mechanism for handling non-native binary formats is using 'binfmt_misc'. 

I developed a custom handler (for XOR encrypted ELF), mounted the binfmt_misc, and registered the new handler
based on the magic numbers (\x7f\x45\x4c\x46 encrypted with XOR).

The implemention concept is similar to the kernel module solution: I receive an encrypted file, conducts a set
of verification steps, decrypts the file and invokes the system call exec() with the decrypted file.
