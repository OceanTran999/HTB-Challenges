![Chal](https://github.com/user-attachments/assets/694dd374-4cd6-47ac-82f5-0e0df758acef)

Check file's protection, we can see that only PIE (Position Independent Code) is disabled, which means the program does not change the address every time it runs.

![file_checksec](https://github.com/user-attachments/assets/b57a0c90-6d4f-4aab-a19e-c31f649ab5dc)


Now, let's see all the functions using `IDA Pro`, I have to convert name of some variables to make it easier to see.

![main](https://github.com/user-attachments/assets/1d8c18fb-3758-470b-9681-49bef16a3869)


![view_grade](https://github.com/user-attachments/assets/4a06c13d-f627-4685-802d-58b1773df9dc)


![400FD5_func](https://github.com/user-attachments/assets/cf3c2ee7-605c-48ec-9daf-fe207f7143bc)


At first I think I have to use Integer Overflow to solve this challenge LOL XD.

![Int_range](https://github.com/user-attachments/assets/3ef06416-d47f-4327-82d0-5afcc4735861)


![run1](https://github.com/user-attachments/assets/ab1b5984-ae99-4e4c-b669-cfc5d4bccc95)


![run2_int-overflow](https://github.com/user-attachments/assets/24667240-9b7e-4c1e-9838-a385e046fa47)


So... what should we do? In line 13 of `sub_400fd5` function, I see that the program does not check whether the size of grade is valid. So we can use buffer overflow vulnerabitlity to exploit by creating a size bigger than `v11[33]` array and overflow by elements. Okay, now we know the vulnerability, the next step is, how can we bypass **Canary**? Welp, I search Google and find this interesting blog https://rehex.ninja/posts/scanf-and-hateful-dot/. When you reach the `rbp-8` position in the stack which the cananry is located here, you just need to input the dot `.`, the program will skip it without modifying the canary value. To make sure this is correct, I use `GDB` to check and yeah, it works.

![canary](https://github.com/user-attachments/assets/aa4bc13d-1a7c-45ec-b8a9-27ed9d976866)


Perfect!!! Now we just need to use basic `ROP` technique to exploit the remote server. Finding some useful gadgets.

![pop_rdi](https://github.com/user-attachments/assets/2ee2a5b5-e30a-47c8-914e-71bf2aebc6c1)


![ret](https://github.com/user-attachments/assets/88bd8b8e-c524-47b2-b2a3-a7ee566c9a66)


Then find at least 2 functions to find the version of libc in remote server, and use `ret2libc` technique to get the shell.

![leak_address1](https://github.com/user-attachments/assets/d68571b0-1575-4dea-a54c-93e1f1711cc5)


![leak_address2](https://github.com/user-attachments/assets/14afc08a-24a4-4d47-a829-953bc7083ece)


![libc_dtb](https://github.com/user-attachments/assets/9c36b15b-6f78-43c0-9ccd-5602b31ae029)


![flag](https://github.com/user-attachments/assets/7e861147-f5dc-4af9-9c20-2ee7f0a32328)
