/*
==================================================================================================
'File' Command based on libelf
> Prints : architecture, class, endianess, OS/ABI, entry point, file type, sections, symbol table

> Compilation : gcc -Wall -Werror minimal_file_lelf.c -o elfloader -lelf
> Usage :       ./elfloader file [file has to be type ELF]
==================================================================================================
*/

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

#define DIE(...) \
    do { \
        printf(__VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)


void print_symbol_table(Elf *elf, Elf_Scn *scn) {
    Elf_Data *data;
    GElf_Shdr shdr;
    int count = 0;

    /* Get the descriptor.  */
    if (gelf_getshdr(scn, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

    data = elf_getdata(scn, NULL);
    count = shdr.sh_size / shdr.sh_entsize;

    printf("\033[1mSymbol table:\033[0m\n");
    for (int i = 0; i < count; ++i) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC || ELF64_ST_TYPE(sym.st_info) == STT_OBJECT)
            printf("0x%0lx %x %s\n", sym.st_value, sym.st_info, elf_strptr(elf, shdr.sh_link, sym.st_name));
    }
}

void print_ELF_info(GElf_Ehdr ehdr){
    printf("Architecture : ");
    switch (ehdr.e_machine)
    {
    case EM_386: printf("x86 32-bit\n"); break;
    case EM_PPC: printf("PowerPC\n"); break;
    case EM_PPC64: printf("PowerPC 64-bit\n"); break;
    case EM_ARM: printf("ARM 32-bit\n"); break;
    case EM_X86_64: printf("x86-64\n"); break;
    case EM_AARCH64: printf("ARM 64-bit\n"); break;
    case EM_RISCV: printf("RISC-V\n"); break;
    case EM_MIPS: printf("MIPS\n"); break;
    case EM_S390: printf("IBM S/390\n"); break;
    case EM_IA_64: printf("Intel Itanium\n"); break;
    default: printf("Unknown"); break;
    }

    printf("Class : ");
    if(ehdr.e_ident[EI_CLASS] == ELFCLASS64){
        printf("64 bit\n");
    } else {
        printf("32 bit\n");
    }

    printf("Endianess : ");
    if(ehdr.e_ident[EI_DATA] == ELFDATA2LSB){
        printf("Little Endian\n");
    } else {
        printf("Big Endian\n");
    }

    printf("OS/ABI : ");
    switch (ehdr.e_ident[EI_OSABI])
    {
    case ELFOSABI_SYSV: printf("UNIX_SYSTEM V\n"); break;
    case ELFOSABI_LINUX: printf("Linux\n"); break;
    case ELFOSABI_FREEBSD: printf("FreeBSD\n"); break;
    case ELFOSABI_SOLARIS: printf("Solaris\n"); break;    
    default: printf("Unknown\n"); break;
    }

    printf("Entry Point : 0x%lx\n",ehdr.e_entry);
    printf("File Type : ");
    switch (ehdr.e_type)
    {
    case ET_EXEC : printf("Executable\n"); break;
    case ET_DYN: printf("Shared Library\n"); break;
    case ET_REL: printf("Relocatable Object\n"); break;
    case ET_CORE: printf("Core Dump\n"); break;
    case ET_NONE: printf("Uknown\n"); break;
    }
}

char *section_type(uint32_t type) {
    switch (type) {
    case SHT_NULL: return "NULL";
    case SHT_PROGBITS: return "PROGBITS";
    case SHT_SYMTAB: return "SYMTAB";
    case SHT_STRTAB: return "STRTAB";
    case SHT_RELA: return "RELA";
    case SHT_HASH: return "HASH";
    case SHT_DYNAMIC: return "DYNAMIC";
    case SHT_NOTE: return "NOTE";
    case SHT_NOBITS: return "NOBITS";
    case SHT_REL: return "REL";
    case SHT_DYNSYM: return "DYNSYM";
    case SHT_INIT_ARRAY: return "INIT_ARRAY";
    case SHT_FINI_ARRAY: return "FINI_ARRAY";
    case SHT_GNU_HASH: return "GNU_HASH";
    case SHT_GNU_versym: return "GNU_versym";
    case SHT_GNU_verneed: return "GNU_verneed";
    default: return "UNKNOWN";
    }
}

void load_file(char *filename) {
    // Elf file discriptor
    Elf *elf; 
    // Elf file section descriptor
    Elf_Scn *symtab = NULL;
    
    // CHECK if readable file format
    if (elf_version(EV_CURRENT) == EV_NONE) 
        DIE("(version) %s", elf_errmsg(-1));
    
    // INIT file descryptor
    int fd = open(filename, O_RDONLY);

    // CHECK if file descryptor initialized
    elf = elf_begin(fd, ELF_C_READ, NULL); 
    if (!elf) 
        DIE("(begin) %s", elf_errmsg(-1));

    GElf_Shdr shdr; // section header
    size_t shstrndx; // section header sting table index
    
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)  
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    GElf_Ehdr ehdr; // INIT header
    // CHECK if header loaded correctly
    if (gelf_getehdr(elf, &ehdr) == NULL)
        DIE("(getehdr) %s", elf_errmsg(-1));
    // PRINT info()
    print_ELF_info(ehdr);

    // INIT scan
    Elf_Scn *scn = NULL;
    printf("\033[1mSections:\033[0m\n");
    int s_index = 0;
    // LOOP through sections & print 
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));
        const char *section = section_type(shdr.sh_type);
        printf("[%2d] %-20s %-10s 0x%0lx 0x%lx 0x%lx\n", s_index++, 
            elf_strptr(elf, shstrndx, shdr.sh_name), 
            section, shdr.sh_addr, shdr.sh_offset, shdr.sh_size);

        // CHECK for symtable
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab")) 
            symtab = scn;
    }
    if (symtab == NULL)
        DIE("No .symtab section found");

    print_symbol_table(elf, symtab);
}

int main(int argc, char *argv[]) {
    if (argc < 2) 
        DIE("usage: elfloader <filename>");
    
    printf("\033[1mELF Analysis\033[0m\n");
    printf("Filename : %s\n",argv[1]);
    load_file(argv[1]);
    return 1;
}
