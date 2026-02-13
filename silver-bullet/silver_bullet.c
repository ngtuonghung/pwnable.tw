#define 48 0x30

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct Wolf Wolf, *PWolf;

typedef ulong size_t;

struct Wolf {
    size_t hp;
    char *name;
};

typedef struct Bullet Bullet, *PBullet;

struct Bullet {
    char description[48];
    size_t power;
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

typedef longlong __quad_t;

typedef __quad_t __off64_t;

struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
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
    char _unused2[40];
};

struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct _IO_FILE FILE;

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef uint __useconds_t;

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

struct evp_pkey_ctx_st {
};

typedef enum Elf32_DynTag_x86 {
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
} Elf32_DynTag_x86;

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_x86 {
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
} Elf_ProgramHeaderType_x86;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType_x86 p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef struct Elf32_Dyn_x86 Elf32_Dyn_x86, *PElf32_Dyn_x86;

struct Elf32_Dyn_x86 {
    enum Elf32_DynTag_x86 d_tag;
    dword d_val;
};

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
};

typedef struct GnuBuildId GnuBuildId, *PGnuBuildId;

struct GnuBuildId {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    byte hash[20];
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef enum Elf_SectionHeaderType_x86 {
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
} Elf_SectionHeaderType_x86;

typedef struct NoteAbiTag NoteAbiTag, *PNoteAbiTag;

struct NoteAbiTag {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    dword abiType; // 0 == Linux
    dword requiredKernelVersion[3]; // Major.minor.patch
};

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_x86 sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
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
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};



undefined main;
undefined __libc_csu_fini;
undefined __libc_csu_init;
undefined1 completed.7200;
undefined4 stdin;
undefined4 stdout;
pointer __frame_dummy_init_array_entry;

// WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

int _init(EVP_PKEY_CTX *ctx)

{
    int iVar1;
    
    iVar1 = __gmon_start__();
    return iVar1;
}



void FUN_08048480(void)

{
    (*(code *)NULL)();
    return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
    ssize_t sVar1;
    
    sVar1 = read(__fd,__buf,__nbytes);
    return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
    int iVar1;
    
    iVar1 = printf(__format);
    return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int usleep(__useconds_t __useconds)

{
    int iVar1;
    
    iVar1 = usleep(__useconds);
    return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
    int iVar1;
    
    iVar1 = puts(__s);
    return iVar1;
}



void __gmon_start__(void)

{
    __gmon_start__();
    return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
                    // WARNING: Subroutine does not return
    exit(__status);
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
    size_t sVar1;
    
    sVar1 = strlen(__s);
    return sVar1;
}



void __libc_start_main(void)

{
    __libc_start_main();
    return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
    int iVar1;
    
    iVar1 = setvbuf(__stream,__buf,__modes,__n);
    return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
    void *pvVar1;
    
    pvVar1 = memset(__s,__c,__n);
    return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int atoi(char *__nptr)

{
    int iVar1;
    
    iVar1 = atoi(__nptr);
    return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strncat(char *__dest,char *__src,size_t __n)

{
    char *pcVar1;
    
    pcVar1 = strncat(__dest,__src,__n);
    return pcVar1;
}



void processEntry _start(undefined4 param_1,undefined4 param_2)

{
    undefined1 auStack_4 [4];
    
    __libc_start_main(main,param_2,&stack0x00000004,__libc_csu_init,__libc_csu_fini,param_1,
                      auStack_4);
    do
    {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
}



// WARNING: This is an inlined function

void __x86_get_pc_thunk_bx(void)

{
    return;
}



// WARNING: Removing unreachable block (ram,0x0804853f)
// WARNING: Removing unreachable block (ram,0x08048548)

void deregister_tm_clones(void)

{
    return;
}



// WARNING: Removing unreachable block (ram,0x08048578)
// WARNING: Removing unreachable block (ram,0x08048581)

void register_tm_clones(void)

{
    return;
}



void __do_global_dtors_aux(void)

{
    if (completed_7200 == '\0')
    {
        deregister_tm_clones();
        completed_7200 = '\x01';
    }
    return;
}



// WARNING: Removing unreachable block (ram,0x080485d9)
// WARNING: Removing unreachable block (ram,0x080485d0)

void frame_dummy(void)

{
    register_tm_clones();
    return;
}



ssize_t read_input(char *buf,size_t len)

{
    ssize_t cnt;
    
    cnt = read(0,buf,len);
    if (cnt < 1)
    {
        puts("read error");
                    // WARNING: Subroutine does not return
        exit(1);
    }
    if (buf[cnt + -1] == '\n')
    {
        buf[cnt + -1] = '\0';
    }
    return cnt;
}



int read_int(void)

{
    int iVar1;
    char local_1c [20];
    ssize_t local_8;
    
    local_8 = read(0,local_1c,0xf);
    if (local_8 < 1)
    {
        puts("read error");
                    // WARNING: Subroutine does not return
        exit(1);
    }
    iVar1 = atoi(local_1c);
    return iVar1;
}



void init_proc(void)

{
    setvbuf(stdout,NULL,2,0);
    setvbuf(stdin,NULL,2,0);
    return;
}



void menu(void)

{
    puts("+++++++++++++++++++++++++++");
    puts("       Silver Bullet       ");
    puts("+++++++++++++++++++++++++++");
    puts(" 1. Create a Silver Bullet ");
    puts(" 2. Power up Silver Bullet ");
    puts(" 3. Beat the Werewolf      ");
    puts(" 4. Return                 ");
    puts("+++++++++++++++++++++++++++");
    printf("Your choice :");
    return;
}



undefined4 beat(Bullet *bullet,Wolf *wolf)

{
    undefined4 wolf_die;
    
    if (bullet->description[0] == '\0')
    {
        puts("You need create the bullet first !");
        wolf_die = 0;
    }
    else
    {
        puts(">----------- Werewolf -----------<");
        printf(" + NAME : %s\n",wolf->name);
        printf(" + HP : %d\n",wolf->hp);
        puts(">--------------------------------<");
        puts("Try to beat it .....");
        usleep(1000000);
        wolf->hp = wolf->hp - bullet->power;
        if ((int)wolf->hp < 1)
        {
            puts("Oh ! You win !!");
            wolf_die = 1;
        }
        else
        {
            puts("Sorry ... It still alive !!");
            wolf_die = 0;
        }
    }
    return wolf_die;
}



void create_bullet(Bullet *bullet)

{
    size_t len;
    
    if (bullet->description[0] == '\0')
    {
        printf("Give me your description of bullet :",0);
        read_input(bullet->description,48);
        len = strlen(bullet->description);
        printf("Your power is : %u\n",len);
        bullet->power = len;
        puts("Good luck !!");
    }
    else
    {
        puts("You have been created the Bullet !");
    }
    return;
}



void power_up(Bullet *bullet)

{
    char buf [48];
    size_t len;
    
    len = 0;
    memset(buf,0,48);
    if (bullet->description[0] == '\0')
    {
        puts("You need create the bullet first !");
    }
    else if (bullet->power < 48)
    {
        printf("Give me your another description of bullet :");
        read_input(buf,48 - bullet->power);
        strncat(bullet->description,buf,48 - bullet->power);
        len = strlen(buf);
        len = bullet->power + len;
        printf("Your new power is : %u\n",len);
        bullet->power = len;
        puts("Enjoy it !");
    }
    else
    {
        puts("You can\'t power up any more !");
    }
    return;
}



undefined4 main(void)

{
    int choice;
    Wolf wolf;
    Bullet bullet;
    
    init_proc();
    bullet.power = 0;
    memset(&bullet,0,48);
    wolf.hp = 0x7fffffff;
    wolf.name = "Gin";
    do
    {
        while( true )
        {
            while( true )
            {
                menu();
                choice = read_int();
                if (choice != 2) break;
                power_up(&bullet);
            }
            if (2 < choice) break;
            if (choice == 1)
            {
                create_bullet(&bullet);
            }
            else
            {
invalid:
                puts("Invalid choice");
            }
        }
        if (choice != 3)
        {
            if (choice == 4)
            {
                puts("Don\'t give up !");
                    // WARNING: Subroutine does not return
                exit(0);
            }
            goto invalid;
        }
        choice = beat(&bullet,&wolf);
        if (choice != 0)
        {
            return 0;
        }
        puts("Give me more power !!");
    } while( true );
}



// WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

void __libc_csu_init(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
    int iVar1;
    EVP_PKEY_CTX *in_stack_ffffffe4;
    
    _init(in_stack_ffffffe4);
    iVar1 = 0;
    do
    {
        (*(code *)(&__frame_dummy_init_array_entry)[iVar1])(param_1,param_2,param_3);
        iVar1 = iVar1 + 1;
    } while (iVar1 != 1);
    return;
}



void __libc_csu_fini(void)

{
    return;
}



// WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

void _fini(void)

{
    return;
}


