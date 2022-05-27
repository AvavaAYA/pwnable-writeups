## 程序分析

#### 漏洞点

 - 没有开启`PIE`且`.bss`段上有不少变量，例如`author`后面就紧跟着堆块的指针
 - 对分配的`chunk`大小没有限制
 - 2.23的`libc`，可以用`IO`利用中的`FSOP`来打  

 - 注意到程序自定义的输入函数存在`\x00`处理的问题:  
```c++
__int64 __fastcall my_getLine(char *a1, unsigned int a2)
{
  int chk; // [rsp+1Ch] [rbp-4h]

  chk = _read_chk(0LL, a1, a2, a2);
  if ( chk < 0 )
  {
    puts("read error");
    exit(1);
  }
  if ( a1[chk - 1] == 10 )                      // no \n, no '\x00'
    a1[chk - 1] = 0;
  return (unsigned int)chk;
}
```

 - 同时`editPage`中使用`strlen`来更新堆块的size，这样就有机会修改到下一个chunk的`size`域

 - 注意到`addPage`函数中数组越界的问题:  
```c++
for ( i = 0; ; ++i )
  {
    if ( i > 8 )								// out_of_bound
      return puts("You can't add new page anymore!");
    if ( !contPtr[i] )
      break;
  }
```

--------

#### 难点

 - 没有提供`free`功能

--------

## 漏洞利用

由于程序中没有`free`，因此考虑[House_of_Orange](#补充内容):  

 - 分配一块

## 补充内容

#### brk和mmap

当程序需要分配的内存空间`size > top_chunk.size`时`sysmalloc`中有两种拓展方式:  

 - `size < mp_.mmap_threshold`
 	`brk`会将数据段`.data`的最高地址指针`_edata`往高地址推，可以通过这种方式在程序没有`free`功能时得到一块`unsorted_bin chunk`( 这种利用方法也常常被称为为`House_of_Orange` )

 - `size>= mp_.mmap_threshold`
 	`mmap`直接向操作系统申请内存: 在进程的虚拟地址空间中( 堆和栈中间，称为文件映射区域的地方 )找一块空闲的虚拟内存，其地址与`libc_base`也有固定的偏移量，可用来进行`leak`( 记得`AsisCTF-2016-b00ks`就是这么做的 )

