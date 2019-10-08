# Phantom DLL hollowing

DLL hollowing is a technique which can be used to provide stealth for malware in memory, either within the local process or a remote one (in combination with process injection/hollowing). This PoC code is associated with the blog post at https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing

This solution contains two projects. The first is a PoC which can execute DLL hollowing using either the classic or phantom (TxF) method. It takes a user-supplied shellcode and only targets the address space of the local process. The second project is a memory scanner, which can enumerate the regional attributes of a user-provided PID, or all accessible processes. It can also collect statistics on the most common permissions for different types of memory.

# Compilation

Visual Studio Community 2019
Release|x86
Release|x64

# Usage

![Usage](https://github.com/forrest-orr/phantom-dll-hollower-poc/blob/master/PhantomDllHollower/Usage.PNG)

PhantomDllHollower.exe (shellcode file path) "txf" (optional, phantom hollow using TxF)
