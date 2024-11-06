# Buffer overflow PrivEsc

# Buffer overflow PrivEsc

## Information gathering

For the this last writeup, we now have access to zaz's home. And inside that, we find that there is in an executable there called `exploit_me` with an suid on user and group. And interesting ! It belongs to root and I'm the zaz group.

```text
zaz@BornToSecHackMe:~$ ls -la
total 12
drwxr-x--- 4 zaz      zaz   147 Oct 15  2015 .
drwxrwx--x 9 www-data root  126 Oct 13  2015 ..
-rwxr-x--- 1 zaz      zaz     1 Oct 15  2015 .bash_history
-rwxr-x--- 1 zaz      zaz   220 Oct  8  2015 .bash_logout
-rwxr-x--- 1 zaz      zaz  3489 Oct 13  2015 .bashrc
drwx------ 2 zaz      zaz    43 Oct 14  2015 .cache
-rwsr-s--- 1 root     zaz  4880 Oct  8  2015 exploit_me
drwxr-x--- 3 zaz      zaz   107 Oct  8  2015 mail
-rwxr-x--- 1 zaz      zaz   675 Oct  8  2015 .profile
-rwxr-x--- 1 zaz      zaz  1342 Oct 15  2015 .viminfo
```

This means that when we execute this, it will be executed on behalf of root. So let's see what that program does by sending it to ghidra to figure it out. We get this very simple main :

```c
bool main(int ac,char **av)

{
  char buff [140];
  
  if (1 < ac) {
    strcpy(buff,av[1]);
    puts(buff);
  }
  return ac < 2;
}
```

It just copies the first argument to a 140 characters long buffer using `strcpy` and displays it on stdout using `puts`. And since strcpy will only stop when it encounters `\x00`, if the argument is longer than the buffer then it will overflow onto the stack.

For instance, here it crashes :
```text
zaz@BornToSecHackMe:~$ ./exploit_me $(python -c 'print("a"*144)')
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```

So, we've found the vulnerability which is a stack based buffer overflow, and now, we have to exploit it.

Let's see if any flag that could make exploitation difficult using `checksec` :

```text
$> py -m checksec exploit_me
┏━━━━━━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ File        ┃ NX  ┃ PIE  ┃ Canary  ┃ Relro  ┃ RPATH  ┃ RUNPATH ┃ Symbols ┃ FORTIFY ┃ Fortified ┃ Fortifiable ┃ Fortify Score ┃
┡━━━━━━━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ exploit_me  │ No  │  No  │   No    │   No   │   No   │   No    │   Yes   │   No    │    No     │     No      │       0       │
└─────────────┴─────┴──────┴─────────┴────────┴────────┴─────────┴─────────┴─────────┴───────────┴─────────────┴───────────────┘
```

NX is disabled to the stack is executable, there is no Canary so we can directly overflow without triggering any segfault, no Relro so we can rewrite the Global Offset Table. In short, there is absolutely no security enabled on the binary's side. On the side of the OS too as ASLR is disabled as demonstrated by checking the content of `/proc/sys/`

```text
zaz@BornToSecHackMe:~$ cat /proc/sys/kernel/randomize_va_space
0
```

ASLR is basically so that the offset of the stack is randomized. This means that if we were to overwrite an address so that it points somewhere we want we wouldn't need to leak any address. We can just try using a debugger such as gdb and use that same offset.

## The plan

Since there is no security at all, there are multiple techniques but we'll use a basic exploitation technique which consists of overwriting the return instruction pointer (RIP) so that it points to an executable sections of the code that we control. To understand, what that is, we need to understand how functions are called and it is quite simple.

A function call is just a JUMP instruction with extra steps. Before, we "jump" to our function using CALL, our program needs to remember where it was in order to return there when the function is done. In order, to do that it uses a stack which stores thoses adresses and it's convenient that it is a stack because the last address from the last function call will be accesible from a simple POP.

So when, we call a function 3 things happen :
- The program pushes the address that points to the next instruction onto the stack.
- Then the program jumps to the function
- When the function is finished, it'll call RET which will pop the address and go there.

So our goal is just to rewrite the top of that stack so that when it calls RET, it actually points to the start of our buffer that'll contain our shellcode and it is executable.

TLDR :
- Write the shellcode
- Overwrite the RIP to pointer to that shellcode
- And enjoy the root

## The exploit