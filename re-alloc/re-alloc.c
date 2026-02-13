#define 120 0x78

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long    qword;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef long __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;0x000000000040113f
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[20];
};

struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct _IO_FILE FILE;

typedef void (*__sighandler_t)(int);

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

struct evp_pkey_ctx_st {
};

typedef enum Elf_ProgramHeaderType {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482
} Elf_ProgramHeaderType;

typedef struct Elf64_Shdr Elf64_Shdr, *PElf64_Shdr;

typedef enum Elf_SectionHeaderType {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191
} Elf_SectionHeaderType;

struct Elf64_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType sh_type;
    qword sh_flags;
    qword sh_addr;
    qword sh_offset;
    qword sh_size;
    dword sh_link;
    dword sh_info;
    qword sh_addralign;
    qword sh_entsize;
};

typedef struct Elf64_Dyn Elf64_Dyn, *PElf64_Dyn;

typedef enum Elf64_DynTag {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf64_DynTag;

struct Elf64_Dyn {
    enum Elf64_DynTag d_tag;
    qword d_val;
};

typedef struct Elf64_Rela Elf64_Rela, *PElf64_Rela;

struct Elf64_Rela {
    qword r_offset; // location to apply the relocation action
    qword r_info; // the symbol table index and the type of relocation
    qword r_addend; // a constant addend used to compute the relocatable field value
};

typedef struct GnuBuildId GnuBuildId, *PGnuBuildId;

struct GnuBuildId {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    byte hash[20];
};

typedef struct Elf64_Ehdr Elf64_Ehdr, *PElf64_Ehdr;

struct Elf64_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    qword e_entry;
    qword e_phoff;
    qword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

typedef struct Elf64_Phdr Elf64_Phdr, *PElf64_Phdr;

struct Elf64_Phdr {
    enum Elf_ProgramHeaderType p_type;
    dword p_flags;
    qword p_offset;
    qword p_vaddr;
    qword p_paddr;
    qword p_filesz;
    qword p_memsz;
    qword p_align;
};

typedef struct NoteAbiTag NoteAbiTag, *PNoteAbiTag;

struct NoteAbiTag {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    dword abiType; // 0 == Linux
    dword requiredKernelVersion[3]; // Major.minor.patch
};

typedef struct Elf64_Sym Elf64_Sym, *PElf64_Sym;

struct Elf64_Sym {
    dword st_name;
    byte st_info;
    byte st_other;
    word st_shndx;
    qword st_value;
    qword st_size;
};



undefined main;
undefined __libc_csu_fini;
undefined __libc_csu_init;
undefined1 completed.7963;
undefined handler;
undefined8 stdout;
undefined8 stdin;
undefined8 stderr;
char *[2] heap;
undefined DAT_00402070;
undefined d_format;
pointer __frame_dummy_init_array_entry;

int _init(EVP_PKEY_CTX *ctx)

{
    int iVar1;
    
    iVar1 = __gmon_start__();
    return iVar1;
}



void FUN_00401020(void)

{
    (*(code *)NULL)();
    return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void _exit(int __status)

{
                    // WARNING: Subroutine does not return
    _exit(__status);
}



void __read_chk(void)

{
    __read_chk();
    return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
    int iVar1;
    
    iVar1 = puts(__s);
    return iVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
    int iVar1;
    
    iVar1 = printf(__format);
    return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint alarm(uint __seconds)

{
    uint uVar1;
    
    uVar1 = alarm(__seconds);
    return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

longlong atoll(char *__nptr)

{
    longlong lVar1;
    
    lVar1 = atoll(__nptr);
    return lVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__sighandler_t signal(int __sig,__sighandler_t __handler)

{
    __sighandler_t p_Var1;
    
    p_Var1 = signal(__sig,__handler);
    return p_Var1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * realloc(void *__ptr,size_t __size)

{
    void *pvVar1;
    
    pvVar1 = realloc(__ptr,__size);
    return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
    int iVar1;
    
    iVar1 = setvbuf(__stream,__buf,__modes,__n);
    return iVar1;
}



void __isoc99_scanf(void)

{
    __isoc99_scanf();
    return;
}



void processEntry _start(undefined8 param_1,undefined8 param_2)

{
    undefined1 auStack_8 [8];
    
    __libc_start_main(main,param_2,&stack0x00000008,__libc_csu_init,__libc_csu_fini,param_1,
                      auStack_8);
    do
    {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
}



void _dl_relocate_static_pie(void)

{
    return;
}



// WARNING: Removing unreachable block (ram,0x0040112d)
// WARNING: Removing unreachable block (ram,0x00401137)

void deregister_tm_clones(void)

{
    return;
}



// WARNING: Removing unreachable block (ram,0x0040116f)
// WARNING: Removing unreachable block (ram,0x00401179)

void register_tm_clones(void)

{
    return;
}



void __do_global_dtors_aux(void)

{
    if (completed_7963 == '\0')
    {
        deregister_tm_clones();
        completed_7963 = 1;
        return;
    }
    return;
}



// WARNING: Removing unreachable block (ram,0x0040116f)
// WARNING: Removing unreachable block (ram,0x00401179)

void frame_dummy(void)

{
    return;
}



void handler(void)

{
    puts("Timeout");
                    // WARNING: Subroutine does not return
    _exit(1);
}



void init_proc(void)

{
    setvbuf(stdin,NULL,2,0);
    setvbuf(stdout,NULL,2,0);
    setvbuf(stderr,NULL,2,0);
    signal(0xe,handler);
    alarm(0x3c);
    return;
}



longlong read_long(void)

{
    longlong lVar1;
    long in_FS_OFFSET;
    char local_28 [24];
    long local_10;
    
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    __read_chk(0,local_28,0x10,0x11);
    lVar1 = atoll(local_28);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28))
    {
                    // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return lVar1;
}



long read_input(char *buf,int len)

{
    int iVar1;
    long lVar2;
    
    iVar1 = __read_chk(0,buf,len,len);
    lVar2 = (long)iVar1;
    if (lVar2 == 0)
    {
        puts("read error");
                    // WARNING: Subroutine does not return
        _exit(1);
    }
    if (buf[lVar2 + -1] == '\n')
    {
        buf[lVar2 + -1] = '\0';
    }
    return lVar2;
}



void allocate(void)

{
    ulong index;
    ulong size;
    char *ptr;
    long n;
    
    printf("Index:");
    index = read_long();
    if ((index < 2) && (heap[index] == NULL))
    {
        printf("Size:");
        size = read_long();
        if (size < 121)
        {
                    // malloc(size)
            ptr = realloc(NULL,size);
            if (ptr == NULL)
            {
                puts("alloc error");
            }
            else
            {
                heap[index] = ptr;
                printf("Data:");
                n = read_input(heap[index],(int)size);
                heap[index][n] = '\0';
            }
        }
        else
        {
            puts("Too large!");
        }
    }
    else
    {
        puts("Invalid !");
    }
    return;
}



void reallocate(void)

{
    ulong index;
    ulong size;
    char *ptr;
    
    printf("Index:");
    index = read_long();
    if ((index < 2) && (heap[index] != NULL))
    {
        printf("Size:");
        size = read_long();
        if (size < 121)
        {
            ptr = realloc(heap[index],size);
            if (ptr == NULL)
            {
                puts("alloc error");
            }
            else
            {
                heap[index] = ptr;
                printf("Data:");
                read_input(heap[index],(int)size);
            }
        }
        else
        {
            puts("Too large!");
        }
    }
    else
    {
        puts("Invalid !");
    }
    return;
}



void rfree(void)

{
    ulong index;
    
    printf("Index:");
    index = read_long();
    if (index < 2)
    {
                    // free(heap[index])
        realloc(heap[index],0);
        heap[index] = NULL;
    }
    else
    {
        puts("Invalid !");
    }
    return;
}



void menu(void)

{
    puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    puts(&DAT_00402070);
    puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    puts("$   1. Alloc               $");
    puts("$   2. Realloc             $");
    puts("$   3. Free                $");
    puts("$   4. Exit                $");
    puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    printf("Your choice: ");
    return;
}



void main(void)

{
    long in_FS_OFFSET;
    int choice;
    undefined8 local_10;
    
    local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
    choice = 0;
    init_proc();
    do
    {
        while( true )
        {
            while( true )
            {
                menu();
                __isoc99_scanf(&d_format,&choice);
                if (choice != 2) break;
                reallocate();
            }
            if (2 < choice) break;
            if (choice == 1)
            {
                allocate();
            }
            else
            {
invalid:
                puts("Invalid Choice");
            }
        }
        if (choice != 3)
        {
            if (choice == 4)
            {
                    // WARNING: Subroutine does not return
                _exit(0);
            }
            goto invalid;
        }
        rfree();
    } while( true );
}



void __libc_csu_init(EVP_PKEY_CTX *param_1,undefined8 param_2,undefined8 param_3)

{
    long lVar1;
    
    _init(param_1);
    lVar1 = 0;
    do
    {
        (*(code *)(&__frame_dummy_init_array_entry)[lVar1])
                  ((ulong)param_1 & 0xffffffff,param_2,param_3);
        lVar1 = lVar1 + 1;
    } while (lVar1 != 1);
    return;
}



void __libc_csu_fini(void)

{
    return;
}



void _fini(void)

{
    return;
}


