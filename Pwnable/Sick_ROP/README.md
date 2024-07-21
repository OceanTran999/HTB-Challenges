![Chal](https://github.com/user-attachments/assets/837554ea-53a1-4766-aacf-2d30eb2faff4)


Check the file's protection, we can see that we can't only execute code in the stack.

![file_checksec](https://github.com/user-attachments/assets/b8a4ce86-a7be-476c-b0fe-9d66819efd96)


The program contains 2 function only.

![start()](https://github.com/user-attachments/assets/dac2193e-96b3-4854-9cd0-a341201062d9)


![vuln()](https://github.com/user-attachments/assets/dc5f70f9-cf4a-4517-afe2-2d88bf4b03ef)


And the saddest is, the program does not give enough gadgets for us to exploit using `ROP` technique.

![ropgadget](https://github.com/user-attachments/assets/170d806f-cabc-4cd4-b51c-21e7a062a617)


However, I see that there's a `syscall` gadget in this program, Google it and I find there is a new technique called SigROP (Sigreturn-oriented programming). In my view, I understand that this technique is used to manipulate the process by undoing everything that was done-changing. For example, in this challenge we can make the program from **non-excutable to excutable** by using this technique.

![wiki](https://github.com/user-attachments/assets/75b33d53-bd33-4805-b997-4f0429e1da94)

Here's the description and the information of `sigreturn()`:

![description](https://github.com/user-attachments/assets/8ac6b960-8cb3-49b3-8118-ec0fd3d1b342)


![rt_sigreturn](https://github.com/user-attachments/assets/feced5bf-17a6-4fdf-81f6-2143d3c8279c)


To call the `sigreturn()` syscall, we need to make the value of `rax` is `15 - 0xf`. Luckily, the challenge provides us the `read()` which will save the number of value we inputted to `rax` register.

![read_func](https://github.com/user-attachments/assets/09d16f57-c3b5-4865-ad93-1276ce0e1e52)


If we input `AAAA`, the `rax` register will be `5` due to including the `NULL` byte. Therefore, we can use `read()` function to call the `rt_sigreturn()` function by giving 14 bytes `A`.

![gdbpeda_r](https://github.com/user-attachments/assets/801998ed-b1f2-4250-997e-f19141eef591)


Now, we just need to find the offset to overwrite the stack, and it's 40 bytes.

![gdbpeda_patterncreate](https://github.com/user-attachments/assets/ed1ff6f5-a8a3-4af2-979d-dc9aeae9b2fd)


![gdbpeda_pattern_offset](https://github.com/user-attachments/assets/9de08fd4-eef2-46a6-9a13-f57dc7330a93)


Using `vmmap` in `gdb-peda`, we can see that the program is from the `0x400000` to `402000`. So we will make this become full `RWX` permsission.

![vmmap](https://github.com/user-attachments/assets/cb4db22d-aa43-4ca7-af1b-449b92b8c42b)


`disasemble vuln` we see that the function is in `0x40102e`, using command `find 0x40102e` we see that there's an address that contains the first instruction of the `vuln()` function, we can use this address to create a new stack and put the shellcode there.

![disas_vuln](https://github.com/user-attachments/assets/aa78db3a-98de-43c7-8e94-eb84ac191f19)


Then... how to change the access protection in the program? Don't worry, `mprotect()` will do it for us. Here's information about this function.

![mprotect()](https://github.com/user-attachments/assets/be571c73-e1b1-40bf-ae01-55649e241d4e)


![mprotect_syscall](https://github.com/user-attachments/assets/8d01cc28-f1a4-4796-a408-ba740e3f156e)


Before using the `ret2shellcode` technique, I will use `GDB` after inputting the code to check if the program has full permissions now.

![shellcode](https://github.com/user-attachments/assets/0f760311-caf4-4695-966a-a9387cce5bc9)


![vmmap2](https://github.com/user-attachments/assets/52f47469-293a-4800-8795-a2520a4eedb1)


And yes, we have all permissions in this challenge. Now, we can see that the `rsi` register's value is `0x4010b8` which is our `40 bytes` offset. So we will put our shellcode here and make the `RIP` point to and execute it. This challenge I will use 23 bytes shellcode from ExploitDB.

![gdbpeda_c](https://github.com/user-attachments/assets/fb04fb80-cc9c-430a-a0de-b5a858185836)


![flag](https://github.com/user-attachments/assets/b2da641b-c8d9-45ab-9cbc-3e80296a4cad)


# References:
https://amriunix.com/posts/sigreturn-oriented-programming-srop/
https://rog3rsm1th.github.io/posts/sigreturn-oriented-programming/
https://cr0mll.github.io/cyberclopaedia/Exploitation/Binary%20Exploitation/Stack%20Exploitation/Sigreturn-oriented%20Programming%20(SROP).html
https://sharkmoos.medium.com/a-quick-demonstration-of-sigreturn-oriented-programming-d9ae98c3ab0e#:~:text=Sigreturn%20Oriented%20Programming%20%28SROP%29%20is%20an%20exploit%20development,order%20to%20jump%20to%20a%20signal%20handler%20routine.
https://anee.me/advanced-rop-techniques-16fd701909b5
