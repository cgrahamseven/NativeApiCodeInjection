# NativeApiCodeInjection
## Examples of how to use the Windows native API for code injection

While the techniques and APIs presented here are not new by any means, the whole goal of this repo is to give a demonstration of how the Windows native API is used to inject code into other processes. Over the years as endpoint security has matured, it has become necessary to shift from using the standard documented Windows API to using certain native APIs to get code running in these environments. 

These days, you can guarantee AV/EDR products have hooked all the popular APIs that have been used in the past to perform code injection. As a result of this, people have had to resort to methods of evading these hooks. Since endpoint software is forced to hook in user mode, the lowest point they can place hooks is in ntdll in every process. Typically, what is done is that a dll will be injected into every process via a kernel mode driver so that it can be loaded as early in the process creation cycle as possible. Once loaded, the dll will place hooks on the native APIs it wants to monitor. Since ntdll essentially provides stub functions that invoke the syscall instruction to enter the kernel, to get around any hooked functions, one can simply invoke their own syscall instruction if the native API system call number is known ahead of time. This is known as direct syscall invocation. This method has become exceptionally popularized in the last few years and there are plenty of examples of how to do it online. 

Hopefully though, if you are not familiar with native API usage, the three code injection techniques shown here will provide some guidance on how to develop your own code that utilizes a direct syscall approach to code injection which is really what you should be striving for in todays environment. 

## Native APIs Used in This Project
- **NtOpenProcess**
- **NtAllocateVirtualMemory**
- **NtFreeVirtualMemory**
- **NtQueryVirtualMemory**
- **NtProtectVirtualMemory**
- **NtReadVirtualMemory**
- **NtWriteVirtualMemory**
- **NtCreateThreadEx**
- **NtQueueApcThread**
- **NtQueryInformationProcess**
- **NtQuerySystemInformation**

## Project Structure
NativeApiCodeInjection.cpp contains 3 functions that inject code in different ways. After compilation, the program takes a single argument which is the process id you want to inject. Since the injected code outputs a debug string to demonstrate success, it is useful to have SysInternals' DebugView running to view the output. 

NativeApi.h contains all the necessary data structures and function pointer declarations for the project. 

To test, you can simply run something like notepad.exe and then run the program and provide the pid for notepad. With DebugView running, you should see 3 'hello' debug strings emitted. 
