# Injector

Process injection methods. Four techniques are implemented: `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, and process hollowing. All methods return an `InjectionResult` so you can check success and inspect error details without catching exceptions.

All methods require elevated privileges or `SeDebugPrivilege` when targeting processes owned by other users or system processes.

---

## Types

### `InjectionMethod`

Enum used by the generic `Inject` dispatcher.

| Value | Description |
|---|---|
| `CreateRemoteThread` | Classic injection via `kernel32.CreateRemoteThread`. |
| `QueueUserAPC` | APC injection into all threads of the target. |
| `ProcessHollowing` | Not dispatched via `Inject` — call `HollowProcess` directly. |
| `NtCreateThreadEx` | Direct NT layer thread creation, bypasses some `kernel32` hooks. |

---

### `InjectionResult`

Returned by every injection method.

| Property | Type | Description |
|---|---|---|
| `Success` | `bool` | Whether the injection completed without error. |
| `ThreadId` | `uint` | Thread ID of the created thread, if applicable. |
| `RemoteBaseAddress` | `IntPtr` | Address of the shellcode in the target process's memory. |
| `LastError` | `int` | Win32 or NTSTATUS error code on failure. |
| `ErrorMessage` | `string` | Human-readable description of the failure. |

---

## Methods

### `InjectCreateRemoteThread(int pid, byte[] shellcode)`

The textbook injection technique. Allocates RW memory in the target, writes shellcode, flips protection to RX, then creates a thread pointing at the shellcode.

Steps performed internally:
1. `OpenProcess(PROCESS_ALL_ACCESS)`
2. `VirtualAllocEx` with `PAGE_READWRITE`
3. `WriteProcessMemory`
4. `VirtualProtectEx` → `PAGE_EXECUTE_READ`
5. `CreateRemoteThread`

```csharp
var shellcode = File.ReadAllBytes("beacon.bin");
var result = Injector.InjectCreateRemoteThread(targetPid, shellcode);

if (result.Success)
    Console.WriteLine($"Thread {result.ThreadId} at 0x{result.RemoteBaseAddress.ToInt64():X}");
else
    Console.WriteLine($"Failed: {result.ErrorMessage} (error {result.LastError})");
```

The remote thread handle is closed immediately after creation — the thread continues running. If you need to wait for it, open the handle yourself using `OpenThread` with the returned `ThreadId`.

---

### `InjectNtCreateThreadEx(int pid, byte[] shellcode)`

Same allocation and write pattern as `CreateRemoteThread`, but uses `NtCreateThreadEx` from ntdll directly instead of `kernel32.CreateRemoteThread`. Some AV/EDR products hook the kernel32 export but not the underlying NT function.

The access mask passed to `NtCreateThreadEx` is `0x1FFFFF` (full thread access).

```csharp
var result = Injector.InjectNtCreateThreadEx(targetPid, shellcode);
```

If `NtCreateThreadEx` returns a negative NTSTATUS, `LastError` will contain the raw status code formatted as `0xC0000XXX`.

---

### `InjectQueueUserAPC(int pid, byte[] shellcode)`

Allocates shellcode in the target process and queues an APC pointing at it to every thread in the process. The shellcode runs when any of those threads enter an alertable wait state (e.g., `SleepEx`, `WaitForSingleObjectEx` with `bAlertable = true`, `MsgWaitForMultipleObjectsEx`).

This technique is noisier than single-thread injection because it touches every thread, but it doesn't create a new thread so it avoids `CreateRemoteThread` detections.

```csharp
var result = Injector.InjectQueueUserAPC(targetPid, shellcode);

if (!result.Success)
    Console.WriteLine(result.ErrorMessage);
    // "QueueUserAPC failed for all threads" means no thread handles could be opened
```

Returns failure if no thread in the process could be opened. Individual `QueueUserAPC` failures per thread are silently skipped — the overall result is success if at least one APC was queued.

---

### `HollowProcess(string targetPath, byte[] peBytes)`

Creates a process in suspended state, unmaps its original image from memory, maps a replacement PE image at the same base address (or a new one), patches the PEB image base pointer, and resumes the primary thread pointing at the replacement's entry point.

The replacement PE must be a native x64 Windows executable. Architecture mismatch will cause the hollowed process to crash on resume.

```csharp
var payload = File.ReadAllBytes("payload.exe");
var result = Injector.HollowProcess(@"C:\Windows\System32\svchost.exe", payload);

if (result.Success)
    Console.WriteLine($"Hollow PID {result.ThreadId}, base 0x{result.RemoteBaseAddress.ToInt64():X}");
```

Steps performed internally:
1. `CreateProcess` with `CREATE_SUSPENDED | CREATE_NO_WINDOW`
2. `NtQueryInformationProcess` (class 0) → get PEB base address
3. Read image base from PEB offset `+0x10`
4. `NtUnmapViewOfSection` to unmap the original image
5. `NtAllocateVirtualMemory` at the payload's preferred base
6. Write PE headers and each section separately
7. Patch the PEB image base field with the new base address
8. `GetThreadContext` → set `RCX` to the new entry point → `SetThreadContext`
9. `ResumeThread`

If any step fails after the process is created, the target process is terminated before returning the failure result.

---

### `Inject(int pid, byte[] shellcode, InjectionMethod method)`

Generic dispatcher. Selects the injection implementation based on `method`. `ProcessHollowing` is not supported through this method — use `HollowProcess` directly.

```csharp
var result = Injector.Inject(targetPid, shellcode, InjectionMethod.NtCreateThreadEx);

// or pick at runtime
var method = elevated ? InjectionMethod.NtCreateThreadEx : InjectionMethod.QueueUserAPC;
var result = Injector.Inject(targetPid, shellcode, method);
```

Passing `InjectionMethod.ProcessHollowing` returns a failure result with `"Unsupported method: ProcessHollowing"` in `ErrorMessage`.

---

## Notes on Memory Cleanup

None of the injection methods free the remote allocation after the thread is created. The shellcode memory stays allocated in the target process for the lifetime of the injected thread. If you need to clean up:

```csharp
// after the thread finishes
Win32.VirtualFreeEx(hProc, result.RemoteBaseAddress, 0, Win32.MEM_RELEASE);
```

---

## Common Failure Modes

`OpenProcess failed (5)` — access denied. Either the target is a protected process or you don't have `SeDebugPrivilege`.

`WriteProcessMemory failed` — the remote address became invalid between allocation and write. Rare but can happen if the target process exits mid-injection.

`NtCreateThreadEx failed: 0xC0000022` — access denied at the NT layer. Usually means the process has a mitigation policy blocking remote thread creation (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES` or similar).

`QueueUserAPC failed for all threads` — either no threads could be opened, or the process has no threads in an alertable state and you need to wait or trigger one.
