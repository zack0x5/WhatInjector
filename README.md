
# WhatInjector

<img src=img/8bit.gif/>

*WhatInjector is a project I made with some cool tricks and techniques to bypass AVs and maybe even some EDRs*

**Techniques** 
* **NTAPI Functions**</br>
  *NTAPI functions are internal functions that are part of ntdll.dll and are poorly documented in Windows. The functions we use, like VirtualAlloc, ReadFile, and OpenProcess, are just wrappers that prepare the parameters to call these NTAPI functions.*
* **HalosGate Technique**</br>
  *HalosGate is an evolution of the HellsGate technique, created with the goal of retrieving syscall numbers (SSNs) even when an EDR hooks certain functions. It iterates over the export tables looking for the target function; once found, it checks the first bytes to see if the EDR is hooking it. If it is, it tries to unhook it; if not, it retrieves the SSN and returns it.*</br>
  *https://github.com/boku7/AsmHalosGate*</br>*https://redops.at/en/blog/exploring-hells-gate*</br>
* **Indirect Syscalls**</br>
  *Indirect syscalls are also an evolution of a technique known as Direct Syscalls. This was a way to solve the problem that Direct Syscalls had: when using Direct Syscalls, the program calls the function directly via the syscall. Since this is somewhat unusual for a legitimate program, EDRs/AVs would detect it and generate an IOC every time a program executes a syscall directly. That’s why Indirect Syscalls emerged—a technique that prepares the parameters in the program but executes the syscall through the function in ntdll. :)*</br>
  *https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls*</br>
  *https://d01a.github.io/syscalls/*</br>
* **Vectored Exception Handling**</br>
  *As previously described in an earlier repository, it is an extension of SEH (Structured Exception Handling) responsible for handling a program's exceptions. It allows programs to manage specific exceptions, and this injector leverages it to execute the shellcode.*</br>
  *https://github.com/zack0x5/VEH-Shellcode-Execution*</br>
  *https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling*</br>

⚠️ **Warning** ⚠️
---
I want to make it clear that the content shared here is for **educational purposes only**. It is not advised to use this example to commit any infractions.
