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
A = lambda len=1, c=b'A': c * len
z = lambda len=1, c=b'\0': c * len

exe = ELF("wannaheap_patched")
libc = ELF("libc-4e5dfd832191073e18a09728f68666b6465eeacd.so")
ld = ELF("./ld-2.24.so")

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on

continue
'''

def conn():
    if args.LOCAL:
        p = process([exe.path])
        sleep(0.25)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
        return p
    else:
        host = "localhost"
        port = 1337
        return remote(host, port)

p = conn()

def Allocate(key, data):
    sla(p, b'>', b'A')
    slan(p, b'key', key)
    sa(p, b'data', data)
    sleep(0.01)

def Read(key):
    sla(p, b'>', b'R')
    slan(p, b'key', key)

slan(p, b'Size', 0x100-1)
sa(p, b'Content', A(0x100))

# Allocate(1, A(24))
# Allocate(1, b'BBBBBBBB')
# Allocate(1, b'BBBBBBBB')
# Allocate(1, b'BBBBBBBB')
# Read(1)
# Read(1)


ia(p)