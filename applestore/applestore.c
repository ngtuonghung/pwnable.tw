#define 7174 0x1c06
#define 7175 0x1c07

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
typedef struct Device Device, *PDevice;

typedef ulong size_t;

struct Device {
    char *name;
    size_t price;
    struct Device *next;
    struct Device *prev;
};

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

typedef void (*__sighandler_t)(int);

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

typedef struct Elf32_Dyn_x86 Elf32_Dyn_x86, *PElf32_Dyn_x86;

struct Elf32_Dyn_x86 {
    enum Elf32_DynTag_x86 d_tag;
    dword d_val;
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

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

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

typedef struct NoteAbiTag NoteAbiTag, *PNoteAbiTag;

struct NoteAbiTag {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    dword abiType; // 0 == Linux
    dword requiredKernelVersion[3]; // Major.minor.patch
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
undefined __libc_csu_init;
undefined __libc_csu_fini;
undefined1 completed.6590;
Device *myCart;
undefined4 stdout;
undefined myCart;
undefined timeout;
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

int fflush(FILE *__stream)

{
    int iVar1;
    
    iVar1 = fflush(__stream);
    return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__sighandler_t signal(int __sig,__sighandler_t __handler)

{
    __sighandler_t p_Var1;
    
    p_Var1 = signal(__sig,__handler);
    return p_Var1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint alarm(uint __seconds)

{
    uint uVar1;
    
    uVar1 = alarm(__seconds);
    return uVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
    void *pvVar1;
    
    pvVar1 = malloc(__size);
    return pvVar1;
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



void __libc_start_main(void)

{
    __libc_start_main();
    return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
    void *pvVar1;
    
    pvVar1 = memset(__s,__c,__n);
    return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int asprintf(char **__ptr,char *__fmt,...)

{
    int iVar1;
    
    iVar1 = asprintf(__ptr,__fmt);
    return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int atoi(char *__nptr)

{
    int iVar1;
    
    iVar1 = atoi(__nptr);
    return iVar1;
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



// WARNING: Removing unreachable block (ram,0x080485c0)
// WARNING: Removing unreachable block (ram,0x080485c9)

void deregister_tm_clones(void)

{
    return;
}



// WARNING: Removing unreachable block (ram,0x080485f9)
// WARNING: Removing unreachable block (ram,0x08048602)

void register_tm_clones(void)

{
    return;
}



void __do_global_dtors_aux(void)

{
    if (completed_6590 == '\0')
    {
        deregister_tm_clones();
        completed_6590 = '\x01';
    }
    return;
}



// WARNING: Removing unreachable block (ram,0x08048649)
// WARNING: Removing unreachable block (ram,0x08048652)

void frame_dummy(void)

{
    register_tm_clones();
    return;
}



void menu(void)

{
    puts("=== Menu ===");
    printf("%d: Apple Store\n",1);
    printf("%d: Add into your shopping cart\n",2);
    printf("%d: Remove from your shopping cart\n",3);
    printf("%d: List your shopping cart\n",4);
    printf("%d: Checkout\n",5);
    printf("%d: Exit\n",6);
    return;
}



void list(void)

{
    puts("=== Device List ===");
    printf("%d: iPhone 6 - $%d\n",1,199);
    printf("%d: iPhone 6 Plus - $%d\n",2,299);
    printf("%d: iPad Air 2 - $%d\n",3,499);
    printf("%d: iPad Mini 3 - $%d\n",4,399);
    printf("%d: iPod Touch - $%d\n",5,199);
    return;
}



void my_read(char *buf,size_t len)

{
    ssize_t sVar1;
    
    sVar1 = read(0,buf,len);
    if (sVar1 == -1)
    {
        puts("Input Error.");
    }
    else
    {
        buf[sVar1] = '\0';
    }
    return;
}



Device * create(char *name,size_t price)

{
    Device *device;
    
    device = malloc(0x10);
    device->price = price;
    asprintf(&device->name,"%s",name);
    device->next = NULL;
    device->prev = NULL;
    return device;
}



void insert(Device *device)

{
    Device *cur_device;
    
    for (cur_device = (Device *)&myCart; cur_device->next != NULL; cur_device = cur_device->next)
    {
    }
    cur_device->next = device;
    device->prev = cur_device;
    return;
}



void add(void)

{
    int device_number;
    int in_GS_OFFSET;
    Device *device;
    char buf [22];
    int local_10;
    
    local_10 = *(int *)(in_GS_OFFSET + 0x14);
    printf("Device Number> ");
    fflush(stdout);
    my_read(buf,0x15);
    device_number = atoi(buf);
    switch(device_number)
    {
    default:
        puts("Stop doing that. Idiot!");
        goto LAB_08048986;
    case 1:
        device = create("iPhone 6",199);
        break;
    case 2:
        device = create("iPhone 6 Plus",299);
        break;
    case 3:
        device = create("iPad Air 2",499);
        break;
    case 4:
        device = create("iPad Mini 3",399);
        break;
    case 5:
        device = create("iPod Touch",199);
    }
    insert(device);
    printf("You\'ve put *%s* in your shopping cart.\n",device->name);
    puts("Brilliant! That\'s an amazing idea.");
LAB_08048986:
    if (local_10 != *(int *)(in_GS_OFFSET + 0x14))
    {
                    // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void delete(void)

{
    int device_number;
    int in_GS_OFFSET;
    int count;
    Device *cur_device;
    char buf [22];
    int local_10;
    Device *next_device;
    Device *prev_device;
    
    local_10 = *(int *)(in_GS_OFFSET + 0x14);
    count = 1;
    cur_device = _myCart;
    printf("Item Number> ");
    fflush(stdout);
    my_read(buf,0x15);
    device_number = atoi(buf);
    do
    {
        if (cur_device == NULL)
        {
LAB_08048a5e:
            if (local_10 != *(int *)(in_GS_OFFSET + 0x14))
            {
                    // WARNING: Subroutine does not return
                __stack_chk_fail();
            }
            return;
        }
        if (count == device_number)
        {
            next_device = cur_device->next;
            prev_device = cur_device->prev;
            if (prev_device != NULL)
            {
                prev_device->next = next_device;
            }
            if (next_device != NULL)
            {
                next_device->prev = prev_device;
            }
            printf("Remove %d:%s from your shopping cart.\n",count,cur_device->name);
            goto LAB_08048a5e;
        }
        count = count + 1;
        cur_device = cur_device->next;
    } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int cart(void)

{
    int in_GS_OFFSET;
    int count;
    int total_price;
    Device *cur_device;
    char buf [22];
    int local_10;
    
    local_10 = *(int *)(in_GS_OFFSET + 0x14);
    count = 1;
    total_price = 0;
    printf("Let me check your cart. ok? (y/n) > ");
    fflush(stdout);
    my_read(buf,0x15);
    if (buf[0] == 'y')
    {
        puts("==== Cart ====");
        for (cur_device = _myCart; cur_device != NULL; cur_device = cur_device->next)
        {
            printf("%d: %s - $%d\n",count,cur_device->name,cur_device->price);
            total_price = total_price + cur_device->price;
            count = count + 1;
        }
    }
    if (local_10 != *(int *)(in_GS_OFFSET + 0x14))
    {
                    // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return total_price;
}



void checkout(void)

{
    int iVar1;
    int in_GS_OFFSET;
    int total_price;
    Device device;
    
    iVar1 = *(int *)(in_GS_OFFSET + 0x14);
    total_price = cart();
    if (total_price == 7174)
    {
        puts("*: iPhone 8 - $1");
        asprintf(&device.name,"%s","iPhone 8");
        device.price = 1;
        insert(&device);
        total_price = 7175;
    }
    printf("Total: $%d\n",total_price);
    puts("Want to checkout? Maybe next time!");
    if (iVar1 != *(int *)(in_GS_OFFSET + 0x14))
    {
                    // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return;
}



void handler(void)

{
    int choice;
    int in_GS_OFFSET;
    char buf [22];
    int local_10;
    
    local_10 = *(int *)(in_GS_OFFSET + 0x14);
    do
    {
        printf("> ");
        fflush(stdout);
        my_read(buf,0x15);
        choice = atoi(buf);
        switch(choice)
        {
        default:
            puts("It\'s not a choice! Idiot.");
            break;
        case 1:
            list();
            break;
        case 2:
            add();
            break;
        case 3:
            delete();
            break;
        case 4:
            cart();
            break;
        case 5:
            checkout();
            break;
        case 6:
            puts("Thank You for Your Purchase!");
            if (local_10 != *(int *)(in_GS_OFFSET + 0x14))
            {
                    // WARNING: Subroutine does not return
                __stack_chk_fail();
            }
            return;
        }
    } while( true );
}



void timeout(void)

{
    puts("Times Up!");
                    // WARNING: Subroutine does not return
    exit(0);
}



void main(void)

{
    signal(0xe,timeout);
    alarm(0x3c);
    memset(&myCart,0,0x10);
    menu();
    handler();
    return;
}



// WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx

void __libc_csu_init(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
    int iVar1;
    EVP_PKEY_CTX *in_stack_ffffffd4;
    
    iVar1 = 0;
    _init(in_stack_ffffffd4);
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


