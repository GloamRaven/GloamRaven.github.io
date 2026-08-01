---
title: "Classic DLL Injection"
date: 2026-08-02 04:50:00 +0900
categories: [Process Injection]
tags: [windows, process-injection, dll-injection, mitre-t1055]
---

## Overview
DLL injection([T1055.001](https://attack.mitre.org/techniques/T1055/001/)) is a process injection technique. If you put your payload in a DLL and inject it, your code runs in another process's context. This write-up shows how to implement the technique in C on Windows 10.

> This series is written for security research and education. All code is run
> against processes on machines I control, inside an isolated VM. Do not use
> these techniques against systems you do not own or have explicit permission to test.
{: .prompt-warning}

## Background
`GetProcAddress` runs in *my* process, but the address it returns is used in the *target* process. This works only because system DLLs are mapped at the same address in every process.

With ASLR enabled, Windows picks a random base address for `kernel32.dll` once per boot. The relocated image is backed by a single section object that every process maps, so the physical pages are shared and the virtual address stays identical across processes for the whole boot session.

That is why `LoadLibraryW` sits at the same address in the injector and in the target, and why the pointer can be passed straight to `CreateRemoteThread`.

Two limits are worth knowing. The address changes after a reboot, so it has to be resolved at run time and can never be hardcoded.

The other limit is bitness: the injector and the target must match. A 32-bit process maps `kernel32.dll` from `SysWOW64`, not `System32`, so an address resolved in a 64-bit injector is meaningless there. Note that on 64-bit Windows `System32` holds the 64-bit binaries and `SysWOW64` holds the 32-bit ones, despite what the names suggest.

## How it works
1. `OpenProcess` - obtain a handle to the target process.
2. `VirtualAllocEx` - allocate a buffer inside the target's address space.
3. `WriteProcessMemory` - copy the DLL path into that buffer.
4. `GetProcAddress` - resolve the address of `LoadLibraryW` in `kernel32.dll`.
5. `CreateRemoteThread` - start a thread in the target whose entry point is `LoadLibraryW` and whose argument is the path written in step 3.

The target process loads the DLL through its own loader, so the payload runs under the target's identity.

## Implementation
```c
    hProc = OpenProcess(
    PROCESS_CREATE_THREAD |		// CreateRemoteThread
    PROCESS_VM_OPERATION |		// VirtualAllocEx
    PROCESS_VM_WRITE,			// WriteProcessMemory
    FALSE, pid);
```
The injector does not request `PROCESS_ALL_ACCESS`. Every right is asked for because a specific API needs it, which follows the principle of least privilege. It also matters for detection: opening another process with full access is a well-known signal that EDR products watch for.

MSDN states that `CreateRemoteThread` requires `PROCESS_CREATE_THREAD`, `PROCESS_QUERY_INFORMATION`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE` and `PROCESS_VM_READ`. The injector requests only three of them and the call still succeeds on Windows 10 x64, so the documented list appears to be wider than what the kernel actually enforces. Measuring the minimum set is the subject of a seperate post.

```c
    SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(WCHAR);
```
The size has to be counted in bytes, not in characters. `dllPath` is a wide string, so each character takes two bytes, and the `+ 1` leaves room for the terminating null.

```c
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pMem, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0) {
        wprintf(L"LoadLibraryW failed inside the target process\n");
        goto cleanup;
    }
    wprintf(L"[+] DLL loaded successfully\n");
```
A non-NULL return from `CreateRemoteThread` only means that the thread was created. It says nothing about whether `LoadLibraryW` succeeded, so the injector also checks the thread's exit code.

Because the thread starts at `LoadLibraryW`, its exit code is that function's return value: a module handle on success, or zero on failure. The value is truncated to 32 bits, so it can only be used as a success flag, not as a real handle.

## Demo
![MessageBox displayed from notepad.exe](/assets/img/dll-injection/demo.PNG){: .shadow}
After running the injector, the message box appears inside notepad.exe.

## Detection
```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 7,8 } -MaxEvents 2 | Format-List TimeCreated, Id, Message


TimeCreated : 2026-08-01 오후 11:43:52
Id          : 7
Message     : Image loaded:
              RuleName: -
              UtcTime: 2026-08-01 14:43:52.212
              ProcessGuid: {e37cd070-fb89-6a6d-1209-000000000700}
              ProcessId: 6744
              Image: C:\Windows\System32\notepad.exe
              ImageLoaded: C:\lab\payload.dll
              FileVersion: -
              Description: -
              Product: -
              Company: -
              OriginalFileName: -
              Hashes: SHA256=A2801992A0EB69AD91BB0ACBE6C2D73F340FB10B950F4440525CB7443750645E
              Signed: false
              Signature: -
              SignatureStatus: Unavailable
              User: DESKTOP-CBM1Q2G\user

TimeCreated : 2026-08-01 오후 11:43:52
Id          : 8
Message     : CreateRemoteThread detected:
              RuleName: -
              UtcTime: 2026-08-01 14:43:52.212
              SourceProcessGuid: {e37cd070-0619-6a6e-6609-000000000700}
              SourceProcessId: 7036
              SourceImage: C:\lab\injector.exe
              TargetProcessGuid: {e37cd070-fb89-6a6d-1209-000000000700}
              TargetProcessId: 6744
              TargetImage: C:\Windows\System32\notepad.exe
              NewThreadId: 7048
              StartAddress: 0x00007FFE09DB0220
              StartModule: C:\Windows\System32\KERNEL32.DLL
              StartFunction: LoadLibraryW
              SourceUser: DESKTOP-CBM1Q2G\user
              TargetUser: DESKTOP-CBM1Q2G\user
```

Every step of this technique is visible to the OS. The two Sysmon events above are enough to identify it on their own.

Event ID 8 records the remote thread. `SourceImage` and `TargetImage` name both sides of the injection, and `StartFunction` resolves the thread's start address to `LoadLibraryW`. A normal program has no reason to start a thread in another process at that particular function.

Event ID 7 records the load that follows. `ImageLoaded` shows the full path of the DLL and `Signed: false` shows that it is unsigned. Because `LoadLibraryW` needs a path on disk, this artifact cannot be avoided.

Both events share the same timestamp and the same target process. Either one alone can produce false positives, but the pair is close to conclusive.

Defenders also watch for `VirtualAllocEx` against another process. My injector only needs `PAGE_READWRITE`, because the bytes it writes are a path string rather than code. RWX allocations are the louder signal, and they show up in the shellcode variants later in this series.

## Limitations
Classic DLL injection has two weaknesses, and both of them shape the techniques that come next.

**The DLL must exist on disk.** `LoadLibraryW` only accepts a file path, so the payload has to be written to a file before it can be loaded. That gives antivirus a file to scan, gives defenders a hash to block, and leaves the DLL path in the target's module list even after the file is deleted.

**Only a function that takes one argument can be started.** `CreateRemoteThread` passes a single value to the thread start routine, so the function it runs has to fit that shape. `LoadLibraryW` takes one pointer and returns one value, which is exactly why it is the classic choice here.

A wrapper function does not solve this. I first thought I could write a helper inside the injector that calls a two-argument function, and pass that helper to `CreateRemoteThread`. That does not work, because the address of my helper is only meaningful inside the injector. The injector image is not mapped into the target process, so the target would start executing whatever happens to live at that address. `LoadLibraryW` works only because `kernel32.dll` is mapped at the same address in both processes.

To run arbitrary code, the code itself has to be copied into the target rather than referenced by address. That is what shellcode injection does, and it removes both limitations at once.

## References
- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

## GitHub
[https://github.com/GloamRaven/windows-process-injection/tree/main/01-dll-injection](https://github.com/GloamRaven/windows-process-injection/tree/main/01-dll-injection)