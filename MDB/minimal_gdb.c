#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <stdint.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <signal.h>
#include <capstone/capstone.h>

#define TOOL "mdb"

#define die(...) \
    do { \
        fprintf(stderr, TOOL": " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)
 
typedef struct {
    char *name;
    uint64_t address;
} Symbol;

// ===== LOAD ELF =====
void load_elf(char *filename, Elf *elf){
    GElf_Ehdr ehdr; 
    // INIT elf file header & CHECK if loaded correctly
    if (gelf_getehdr(elf, &ehdr) == NULL)
        die("(getehdr) %s", elf_errmsg(-1));
    
    // CHECK if given file is executable
    if (ehdr.e_type !=  ET_EXEC)
        die("(not supported file type, use ELF executable)");
}

// ===== LOAD SECTIONS & SYMBOL TABLE ====
void load_sections(Elf *elf, Symbol **symbols, int *sym_count){

    size_t shstrndx;
    // INIT section header sting table index & CHECK if loaded correctly
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)  
        die("(getshdrstrndx) %s", elf_errmsg(-1));
    
    // elf section pointer to STORE symbol table
    Elf_Scn *symtab = NULL;
    // elf section pointer to iterate through sections
    Elf_Scn *scn = NULL;
    // elf section header
    GElf_Shdr shdr;

    // ITERATE through sections & STORE .symtab
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        // INIT section header & CHECK if loaded correctly
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));

        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab")) 
            symtab = scn;
    }

    // symtab not NULL
    if (symtab){
        // INIT .symtab section header & CHECK if loaded correctly
        if (gelf_getshdr(symtab, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));
        
        // GET entry size and string table link from .symtab
        Elf_Data *data = elf_getdata(symtab, NULL);
        // CHECK if data loaded correctly
        if (!data)
            die("(getdata) %s", elf_errmsg(-1));
        if (shdr.sh_entsize == 0)
            die("symbol table entry size is 0");
        
        // find number of symbols (section size / entry size)
        size_t count = shdr.sh_size / shdr.sh_entsize;
        
        *symbols = malloc(count * sizeof(Symbol));
        // CHECK if malloc allocated
        if (!(*symbols))
            die("(malloc) %s",strerror(errno));

        // INIT symbol table entry
        GElf_Sym sym;

        // ITERATE through .symtab entries
        for (size_t i = 0; i < count; i++) {
            // GET symbol data & CHECK if completed correctly
            if (gelf_getsym(data, i, &sym) == NULL)
                die("(getsym) %s",elf_errmsg(-1));

            // if symbol value is 0, skip
            if (sym.st_value == 0) 
                continue;

            // GET symbol name
            char* name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            // CHECK if name load completed correctly
            if (!name)
                die("(strptr) %s",elf_errmsg(-1));

            // STORE symbol name, address(value) and increase symbol count
            (*symbols)[*sym_count].name = strdup(name);
            (*symbols)[*sym_count].address = sym.st_value;
            (*sym_count)++;
        }
    } else // symtab is NULL
    fprintf(stderr,"WARNING no symbol table found, continuing without\n");
    
    return;
}

// ===== FIND DYNAMIC SYMBOLS & PLT ENTRIES ===== 
void load_plt(Elf *elf, Symbol **symbols, int *sym_count) {
    
    size_t shstrndx;
    // INIT section header string table index & CHECK if loaded correctly
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));

    // elf section pointer to ITERATE through sections
    Elf_Scn *scn = NULL;
    // elf section pointer .rela.plt section 
    Elf_Scn *relaplt_scn = NULL;
    // elf section pointer .plt section
    Elf_Scn *plt_scn = NULL;
    // elf section pointer for .dynsym sections
    Elf_Scn *dynsym_scn = NULL;
    // elf section header 
    GElf_Shdr shdr;

    // ITERATE through sections
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        // INIT section header & CHECK if loaded correctly
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));
        
        // TEMP STORE section name
        const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
        // if name is NULL
        if (!name) 
            continue;
        
        if (!strcmp(name, ".rela.plt"))
            relaplt_scn = scn;
        else if (!strcmp(name, ".plt"))
            plt_scn = scn;
        else if (!strcmp(name, ".dynsym"))
            dynsym_scn = scn;
    }

    // CHECK if all three sections found
    if (!relaplt_scn || !plt_scn || !dynsym_scn)
        return;

// .PLT
    GElf_Shdr plt_shdr;
    // GET .plt section header & CHECK if loaded correctly
    if (gelf_getshdr(plt_scn, &plt_shdr) != &plt_shdr)
        die("(getshdr plt) %s", elf_errmsg(-1));

    // STORE .plt address
    uint64_t plt_base = plt_shdr.sh_addr;

// .RELA.PLT
    GElf_Shdr rela_shdr;
    // GET .rela.plt section header & CHECK if loaded correctly
    if (gelf_getshdr(relaplt_scn, &rela_shdr) != &rela_shdr)
        die("(getshdr rela) %s", elf_errmsg(-1));

    // GET .rela.plt section header data
    Elf_Data *rela_data = elf_getdata(relaplt_scn, NULL);
    // CHECK if loaded correctly
    if (!rela_data) 
        die("(getdata rela) %s", elf_errmsg(-1));
    // find number of symbols (section size / entry size)
    size_t rela_count = rela_shdr.sh_size / rela_shdr.sh_entsize;

// .DYNSYM
    GElf_Shdr dyn_shdr;
    // GET .dynsym section header & CHECK if loaded correctly
    if (gelf_getshdr(dynsym_scn, &dyn_shdr) != &dyn_shdr)
        die("(getshdr dynsym) %s", elf_errmsg(-1));

    // GET .dynsym section header data
    Elf_Data *dyn_data = elf_getdata(dynsym_scn, NULL);
    // CHECK if data loaded correctly
    if (!dyn_data) 
        die("(getdata dynsym) %s", elf_errmsg(-1));

    // grow symbols array to fit new entries
    *symbols = realloc(*symbols, (*sym_count + rela_count) * sizeof(Symbol));
    // CHECK if realloc allocated correctly
    if (!*symbols) 
        die("(realloc) %s", strerror(errno));

    GElf_Rela rela;
    // ITERATE through .rela.plt relocation entries
    for (size_t i = 0; i < rela_count; i++) {

        // GET relocation entry & CHECK if loaded correctly
        if (gelf_getrela(rela_data, i, &rela) == NULL) 
            continue;
        // GET symbol index from relocation entry
        uint32_t sym_idx = GELF_R_SYM(rela.r_info);

        GElf_Sym sym;
        // GET symbol & CHECK if loaded correctly
        if (gelf_getsym(dyn_data, sym_idx, &sym) == NULL) 
            continue;

        // GET symbol name from .dynstr (via dyn_shdr.sh_link which points to .dynstr)
        char *name = elf_strptr(elf, dyn_shdr.sh_link, sym.st_name);
        
        // CHECK if name loaded correctly
        if (!name || !*name) 
            continue;
        // for the plt address, from the base skip 0x10(16 bytes) then add 0x10*i to find the address in PLT
        uint64_t plt_addr = plt_base + 0x10 + i * 0x10;

        // STORE symbol name & plt address 
        (*symbols)[*sym_count].name = strdup(name);
        (*symbols)[*sym_count].address = plt_addr;
        (*sym_count)++;
    }
}

typedef struct{
    uint64_t og_address;
    long og_instruction;
    // NULL if addr set manually
    char *symbol;
    // if int3 syscall set or not
    int INT3;
    // initialized symbol or pending
    int pending;
}Breakpoint;

// ===== SET BREAKPOINT =====
void set_breakpoint(int pid, Breakpoint *bp) {
    
    long orig = ptrace(PTRACE_PEEKDATA, pid, bp->og_address, 0);
    // READ original instruction & CHECK if read correctly
    if (orig == -1)
        die("(peekdata) %s", strerror(errno));
    
    // STORE original instruction
    bp->og_instruction = orig & 0xFF;

    // WRITE INT3 & CHECK if wrote correctly
    if (ptrace(PTRACE_POKEDATA, pid, bp->og_address, (orig & 0xFFFFFFFFFFFFFF00) | 0xCC ) == -1)
        die("(pokedata) %s", strerror(errno));
    
    // SET as active
    bp->INT3 = 1;
}

// ===== STEP INSTRUCTION =====
void process_step(int pid,int *status) {

    // single step & CHECK if completed correctly
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));
 
    waitpid(pid, status, 0);
}

// ===== DISASSEMBLE =====
void disassemble(int pid, uint64_t rip, Symbol *symbols, int sym_count){
    // byte buffer to store instructions
    uint8_t poke[80];

    // READ 80 bytes from tracee at rip, 8 bytes each time(PEEKDATA word size)
    for(int i = 0 ; i < 10 ; i++){
        // RESET errno before ptrace call to detect fresh errors
        errno = 0;

        long word = ptrace(PTRACE_PEEKDATA, pid, (rip + i * 8), 0);
        // READ at rip +(i*8) & CHECK if read failed
        if (word == -1 && errno)
            die("(peekdata) %s", strerror(errno));
        
        // COPY word into byte buffer
        memcpy(poke + i * 8, &word, 8);
    }

    // capstone handle
    csh handle;
    // instruction array
    cs_insn *instr;

    // INIT capstone for x86 64-bit & CHECK if init completed correctly
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        die("(capstone)");

    // DISASSEMBLE 11 instructions from poke buffer from rip & returns how many decoded
    size_t count = cs_disasm(handle, poke, sizeof(poke), rip, 11, &instr);

    // CHECK if disassembly failed
    if (!count){
        fprintf(stderr, "Failed to disassemble at 0x%lx\n", rip);
        cs_close(&handle);
        return;
    }
    
    // ITERATE through decoded instructions
    for(size_t i = 0; i < count; i++){
        // capstone default operand string
        char *resolved_op = instr[i].op_str;
        char op_buf[64];
        char *end;

        // try parsing operation address as hex
        uint64_t op_addr = strtoull(instr[i].op_str, &end, 16);
        // CHECK if success in parsing
        if (end != instr[i].op_str){
            // ITERATE through symbols table 
            for(int j = 0; j < sym_count; j++){
                // matching address
                if (symbols[j].address == op_addr){
                    // replace address with symbol
                    snprintf(op_buf, sizeof(op_buf), "%s", symbols[j].name);
                    resolved_op = op_buf;
                    break;
                }
            }
        }
        if (i == 0) // Program Counter
            printf(" > 0x%016lx %-6s %s\n", instr[i].address, instr[i].mnemonic, resolved_op);
        else
            printf("   0x%016lx %-6s %s\n", instr[i].address, instr[i].mnemonic, resolved_op);

        if (strcmp(instr[i].mnemonic, "ret") == 0)
                break;
        
    }
    cs_free(instr, count);
    cs_close(&handle);
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("./mdb ./<program>: %d", argc);
    char *filename = argv[1];

// ===== ELF FD INIT & CHECK FILE TYPE ===== 

    // elf fd
    Elf *elf;
    // CHECK if libelf init correctly
    if (elf_version(EV_CURRENT) == EV_NONE) 
        die("(version) %s", elf_errmsg(-1));
    
    int fd = open(filename, O_RDONLY);
    // CHECK if fd init correctly
    if (fd == -1)
        die("(open) %s", strerror(errno));

    // INIT elf fd 
    elf = elf_begin(fd, ELF_C_READ, NULL);
    // CHECK if elf fd completed correctly
    if (!elf) 
        die("(begin) %s", elf_errmsg(-1));

    // CHECK filetype
    load_elf(filename,elf);

// ===== FIND SYMBOL TABLE & LOAD SECTIONS ===== 

    // symbols array & symbol count
    Symbol *symbols = NULL;
    int sym_count = 0;

    // LOAD .symtab & .dynsym, .plt, .rela.plt
    load_sections(elf, &symbols, &sym_count);
    load_plt(elf, &symbols, &sym_count);

    int br_size = 8;
    // INIT with 8, double if full
    Breakpoint *breakpoints = malloc(br_size*sizeof(Breakpoint));
    // CHECK if malloc allocated correctly
    if (!breakpoints)
         die("(malloc) %s", strerror(errno));
    
    int breakpoint_count = 0;
    int running = 0;
    int last_hit = -1;
    pid_t pid; // tracee setup in r

// ===== COMMAND HANDLER =====
    char in[256];
    while (1) {
        printf("(mdb) > ");
        // SYNC printf with user input
        fflush(stdout);
        // READ user input, breaks when Crtl + D (EOF)
        if (!fgets(in, sizeof(in), stdin))
            break;

// ===== 1. BREAKPOINT ===== 
        if (in[0] == 'b'){

            // A. USER SET ADDRESS
            if (in[1] == ' ' && in[2] == '*'){
                char *end_pointer;
                // RESET errno to detect strtoull overflow
                errno = 0;

                // typecast from string to hex
                uint64_t addr = strtoull(&in[3],&end_pointer,16);

                // CHECK if address loaded correctly (check_pointer points to where in[] stopped being parsed)
                if (end_pointer == &in[3] || errno == ERANGE){
                    printf("INVALID ADDRESS, use hex fomat 'b *0x012345'\n");
                    continue;
                }

                // CHECK if breakpoints is full
                if (breakpoint_count == br_size) {
                    // double size + re-allocate
                    br_size *= 2;
                    breakpoints = realloc(breakpoints, br_size * sizeof(Breakpoint));
                    // CHECK if realloc allocated correctly
                    if (!breakpoints)
                        die("(realloc) %s", strerror(errno));
                }
                // ASSIGN values to breakpoint
                breakpoints[breakpoint_count].og_address = addr;    // assign address to breakpoint
                breakpoints[breakpoint_count].og_instruction = 0;   // will be set when tracee running
                breakpoints[breakpoint_count].symbol = NULL;        // user set, no symbol to point to
                breakpoints[breakpoint_count].INT3 = 0;             // will be set when tracee running
                breakpoints[breakpoint_count].pending = 0;          // user set, found already
                breakpoint_count++;
                printf("Breakpoint %d set at 0x%lx\n", breakpoint_count, addr);              
            }
            // B. SYMBOL ADDRESS
            else if (in[1] == ' '){
                // EDIT symbol name, to end with null terminator rather than new line
                if (in[2 + strlen(&in[2]) - 1] == '\n')
                    in[2 + strlen(&in[2]) - 1] = '\0';
                
                int found = 0;
                // ITERATE through symbols, find match for symbol name
                for (int i = 0; i < sym_count; i++) {
                    if (strcmp(symbols[i].name, &in[2]) == 0) {
                        found = 1;
                        // CHECK if breakpoints is full
                        if (breakpoint_count == br_size) {
                            // double size + re-allocate
                            br_size *= 2;
                            breakpoints = realloc(breakpoints, br_size * sizeof(Breakpoint));
                            // CHECK if realloc allocated correctly
                            if (!breakpoints)
                                die("(realloc) %s", strerror(errno));
                        }
                        // ASSIGN values to breakpoint
                        breakpoints[breakpoint_count].og_address = symbols[i].address;  // assign symbol address to breakpoint
                        breakpoints[breakpoint_count].og_instruction = 0;               // will be set when tracee running
                        breakpoints[breakpoint_count].symbol = strdup(symbols[i].name); // copy symbol name
                        breakpoints[breakpoint_count].INT3 = 0;                         // will be set when tracee running
                        breakpoints[breakpoint_count].pending = 0;                      // found already
                        breakpoint_count++;
                        break;
                    }
                }
                // C. PENDING SYMBOL ADDRESS
                if (!found){
                    printf("Symbol '%s' not found, add as pending? (y/n): ", &in[2]);
                    // SYNC printf with user input
                    fflush(stdout);
                    char ans[4];
                    fgets(ans, sizeof(ans), stdin);
                    if (ans[0] == 'y'){
                        // CHECK if breakpoints is full
                        if (breakpoint_count == br_size) {
                            // double size + re-allocate
                            br_size *= 2;
                            breakpoints = realloc(breakpoints, br_size * sizeof(Breakpoint));
                            // CHECK if realloc allocated correctly
                            if (!breakpoints)
                                die("(realloc) %s", strerror(errno));
                        }
                        // ASSIGN values to breakpoint
                        breakpoints[breakpoint_count].og_address = 0;                   // assign symbol address to breakpoint
                        breakpoints[breakpoint_count].og_instruction = 0;               // will be set when tracee running
                        breakpoints[breakpoint_count].symbol = strdup(&in[2]);          // copy symbol name
                        breakpoints[breakpoint_count].INT3 = 0;                         // will be set when tracee running
                        breakpoints[breakpoint_count].pending = 1;                      // found already
                        breakpoint_count++;
                        printf("Pending breakpoint %d added for '%s'\n", breakpoint_count, &in[2]);
                    }
                    else{
                        printf("Pending breakpoint not added\n");
                    }
                }
            }
            else continue;
        }

// ===== 2. BREAKPOINT LIST =====
        else if (in[0] == 'l'){
            // CHECK if there are breakpoints
            if (breakpoint_count == 0){
                printf("No breakpoints set\n");
                continue;
            }
            // ITERATE through breakpoints and print number, address, name and pending/not pending
            for(int i = 0; i < breakpoint_count ; i++){
                printf("Breakpoint %d at 0x%lx ",i+1,breakpoints[i].og_address);
                if (breakpoints[i].symbol)
                    printf("<%s> ",breakpoints[i].symbol);
                if (breakpoints[i].pending)
                    printf(", pending\n");
                else
                    printf(", not pending\n");
            }
        }

// ===== 3. BREAKPOINT DELETE =====
        else if (in[0] == 'd' && in[1] == ' '){
            if ( breakpoint_count == 0)
                printf("No breakpoints to delete\n");
            else {
                // 3rd char to int, -1 as its 1-based for user 
                int br_del = atoi(&in[2]) - 1;

                // CHECK if valid breakpoint number
                if (br_del < 0 || br_del >= breakpoint_count)
                    printf("Invalid breakpoint number.");
                else {
                    // RESTORE original instruction if INT3 written
                    if (running && breakpoints[br_del].INT3) {
                        errno = 0;
                        // READ current address
                        long current = ptrace(PTRACE_PEEKDATA, pid, breakpoints[br_del].og_address, 0);
                        if (current == -1 && errno)
                            die("(peekdata) %s", strerror(errno));
                        // RESTORE original byte & CHECK if written correctly
                        if (ptrace(PTRACE_POKEDATA, pid, breakpoints[br_del].og_address, ((current & 0xFFFFFFFFFFFFFF00) | breakpoints[br_del].og_instruction)) == -1)
                            die("(pokedata) %s", strerror(errno));
                    }
                           
                    // free symbol if exist
                    if (breakpoints[br_del].symbol)
                        free(breakpoints[br_del].symbol);
                    
                    // reset last_hit, if deleted breakpoint was the one hit
                    if (last_hit == br_del )
                        last_hit = -1;
                    // update last_hit, if the swapped breakpoint was the one hit
                    else if (last_hit == breakpoint_count - 1)
                        last_hit = br_del ;

                    // swap deleted breakpoint with last
                    breakpoints[br_del] = breakpoints[breakpoint_count-1];
                    breakpoint_count--;
                    printf("Breakpoint %d deleted\n",br_del + 1);  
                }
            }
        }
// ===== 4. RUN ===== 
        else if (in[0] == 'r'){
            if (running) {
                printf("Program already running, use 'c' to continue execution\n");
                continue;
            }
            running = 1;

// ===== PTRACE TRACEE SETUP ===== 
            pid = fork();
            switch (pid) {
            // error
            case -1:
                die("%s", strerror(errno));
            case 0:
                // child proccess = ptrace + exec(./argv[1])
                ptrace(PTRACE_TRACEME, 0, 0, 0);
                execvp(argv[1], argv + 1);
                // returns here in case of error
                die("%s", strerror(errno));
            }
            // INIT ptrace
            ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
            waitpid(pid, 0, 0);

            // RESOLVE pending breakpoints
            for(int i = 0; i < breakpoint_count ; i++){
                // skip if not-pending
                if (!breakpoints[i].pending)
                    continue;
                // pending, find breakpoint symbol name in symbols table
                for(int j = 0; j < sym_count ; j++){
                    if (strcmp(symbols[j].name,breakpoints[i].symbol) == 0){
                        // update with new addresses
                        breakpoints[i].og_address = symbols[j].address;
                        breakpoints[i].pending = 0;
                        printf("Pending breakpoint %d resolved: '%s' at 0x%lx\n",i + 1, breakpoints[i].symbol, breakpoints[i].og_address);
                        break;
                    }
                }
                if (breakpoints[i].pending)
                    printf("Pending breakpoint %d '%s' could not be resolved, skipping\n",i + 1, breakpoints[i].symbol);
            }

            // reset INT3 and set all non-pending breakpoints
            for (int i = 0; i < breakpoint_count; i++) {
                breakpoints[i].INT3 = 0;
                if (!breakpoints[i].pending)
                    set_breakpoint(pid, &breakpoints[i]);
            }

            // START tracee
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
                die("(cont) %s", strerror(errno));
            
            int status;
            waitpid(pid, &status, 0); // pass status to waitpid

            // CHECK if child stopped & if stoped because of SIGTRAP(int3)
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
                // INIT register struct
                struct user_regs_struct regs;
                // READ regs & CHECK if register values read correctly
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
                    die("(getregs) %s", strerror(errno));
                
                // ITERATE through breakpoints to find which one hit
                for (int i = 0; i < breakpoint_count; i++) {
                    // CHECK if INT3 executed, rip - 1 as we are in the next instruction
                    if (regs.rip - 1 == breakpoints[i].og_address){
                        errno = 0;
                        // READ current address
                        long current = ptrace(PTRACE_PEEKDATA, pid, breakpoints[i].og_address, 0);
                        if (current == -1 && errno)
                            die("(peekdata) %s", strerror(errno));
                        // WRITE original byte & CHECK if written correctly
                        if (ptrace(PTRACE_POKEDATA, pid, breakpoints[i].og_address, ((current & 0xFFFFFFFFFFFFFF00) | breakpoints[i].og_instruction)) == -1)
                            die("(pokedata) %s", strerror(errno));

                        // bring PC back one byte
                        regs.rip -= 1;

                        // UPDATE registers & CHECK if updated correctly
                        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
                            die("(setregs) %s", strerror(errno));

                        // PRINT breakpoint message
                        printf("Breakpoint %d hit at 0x%lx\n",i+1,breakpoints[i].og_address);
                        if (breakpoints[i].symbol)
                            printf("%s:\n",breakpoints[i].symbol);
                        disassemble(pid, breakpoints[i].og_address, symbols, sym_count);
                        last_hit = i;
                        break;
                    }
                }
            }
            // CHECK if child exited & RESET running, last_hit
            else if (WIFEXITED(status)) {
                printf("Program exited with code %d\n", WEXITSTATUS(status));
                running = 0;
                last_hit = -1;
                continue;
            }
        }

// ===== 5. CONTINUE =====  
        else if (in[0] == 'c'){
            if (!running) {
                printf("Program not running, use 'r' to run the program\n");
                continue;
            }
            // RESET breakpoint if it was hit on continue
            if (last_hit != -1){
                // proceed execution past breakpoint address
                process_step(pid, NULL);
                set_breakpoint(pid, &breakpoints[last_hit]);
                last_hit = -1;
            }

            // START tracee
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
                die("(cont) %s", strerror(errno));
            
            int status;
            waitpid(pid, &status, 0); // pass status to waitpid

            // CHECK if child stopped & if stoped because of SIGTRAP(int3)
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
                // INIT register struct
                struct user_regs_struct regs;
                // READ regs & CHECK if register values read correctly
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
                    die("(getregs) %s", strerror(errno));

                // ITERATE through breakpoints to find which one hit
                for (int i = 0; i < breakpoint_count; i++) {
                    // CHECK if INT3 executed, rip - 1 as we are in the next instruction
                    if (regs.rip - 1 == breakpoints[i].og_address){
                        errno = 0;
                        // READ current address
                        long current = ptrace(PTRACE_PEEKDATA, pid, breakpoints[i].og_address, 0);
                        if (current == -1 && errno)
                            die("(peekdata) %s", strerror(errno));
                        // WRITE original byte CHECK if written correctly
                        if (ptrace(PTRACE_POKEDATA, pid, breakpoints[i].og_address, ((current & 0xFFFFFFFFFFFFFF00) | breakpoints[i].og_instruction)) == -1)
                            die("(pokedata) %s", strerror(errno));
                        
                        // bring PC back one byte
                        regs.rip -= 1;

                        // UPDATE registers & CHECK if updated correctly
                        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
                            die("(setregs) %s", strerror(errno));
                        
                        // PRINT breakpoint message
                        printf("Breakpoint %d hit at 0x%lx\n",i+1,breakpoints[i].og_address);
                        if (breakpoints[i].symbol)
                            printf("%s:\n",breakpoints[i].symbol);
                        disassemble(pid, breakpoints[i].og_address, symbols, sym_count);
                        last_hit = i;
                        break;                        
                    }
                }
            }
            // CHECK if child exited & RESET running, last_hit
            else if (WIFEXITED(status)) {
                printf("Program exited with code %d\n", WEXITSTATUS(status));
                running = 0;
                last_hit = -1;
                continue;
            }
        }

// ===== 6. STEP INSTRUCTION =====       
        else if (strncmp(in,"si",2) == 0){
            if (!running) {
                printf("Program not running, use 'r' to run the program\n");
                continue;
            }
            int status;
            // HANDLE case of breakpoint encountered when step_instruction
            if (last_hit != -1) {
                process_step(pid, &status);
                set_breakpoint(pid, &breakpoints[last_hit]);
                last_hit = -1;
            } else {
                process_step(pid, &status);
            }

            if (WIFEXITED(status)) {
                printf("Program exited with code %d\n", WEXITSTATUS(status));
                running = 0;
                last_hit = -1;
                continue;
            }

            struct user_regs_struct regs;
            // GET regs & CHECK if register values read correctly
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
                die("(getregs) %s", strerror(errno));
            disassemble(pid, regs.rip, symbols, sym_count);
        }

// ===== 7. DISASSEMBLE =====      
        else if (strncmp(in,"disas",5) == 0){
            // CHECK if program running
            if (!running) {
                printf("Program not running, use 'r' to run the program\n");
                continue;
            }
            struct user_regs_struct regs;
            // GET regs & CHECK if register values read correctly
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
                die("(getregs) %s", strerror(errno));
            disassemble(pid, regs.rip, symbols, sym_count);
        }
        else if (in[0] == 'q'){
            // KILL tracee
            if (running)
                kill(pid, SIGKILL);
            
            // FREE allocated memory
            elf_end(elf);
            close(fd);
            for (size_t i = 0; i < sym_count; i++)
                free(symbols[i].name);
            free(symbols);
            for (int i = 0; i < breakpoint_count; i++)
                if (breakpoints[i].symbol)
                    free(breakpoints[i].symbol);
            free(breakpoints);
            return 0;
        }
        else {
            printf("Invalid input, try :\n");
            printf("- BREAKPOINT : 'b <symbol>' OR 'b *<address>' [ pause execution at symbol address or address ]\n\n");
            printf("- LIST BREAKPOINTS : 'l' [ shows a list of all breakpoints issued ]\n\n");
            printf("- DELETE BREAKPOINT : 'd <num>' [ deletes breakpoint num from breakpoint list ]\n\n");
            printf("- RUN PROGRAM : 'r <argv_input>' OR 'r <file_input>' [ runs the program with given input ]\n\n");
            printf("- CONTINUE EXECUTION : 'c' [ continues program execution ]\n\n");
            printf("- STEP INSTRUCTION : 'si' [ executes instruction and stops execution at the next one ]\n\n");
            printf("- DISASSEMBLE : 'disas' [ shows the instruction to be executed and the 10 next ones ]\n");
            printf("- QUIT : 'q' [ stops MDB, kills tracee process & free allocated memory ]\n");
        }
    }
}
