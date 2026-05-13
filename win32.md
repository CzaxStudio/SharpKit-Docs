# Win32

P/Invoke bindings for `kernel32.dll`, `advapi32.dll`, and `ntdll.dll`, plus a few managed helpers built on top of them. Everything here is a thin wrapper — the method names, parameters, and return values match the Windows API documentation directly.

All P/Invoke calls set `SetLastError = true` where applicable. Check `Marshal.GetLastWin32Error()` when a method returns `IntPtr.Zero` or `false`.

---

## Constants

### Process Access Rights

Used as the `dwDesiredAccess` parameter when calling `OpenProcess`.

| Constant | Value | Description |
|---|---|---|
| `PROCESS_ALL_ACCESS` | `0x001FFFFF` | Full access. Requires SeDebugPrivilege on protected processes. |
| `PROCESS_VM_READ` | `0x0010` | Read virtual memory. |
| `PROCESS_VM_WRITE` | `0x0020` | Write virtual memory. |
| `PROCESS_VM_OPERATION` | `0x0008` | Required for `VirtualAllocEx` / `VirtualFreeEx`. |
| `PROCESS_CREATE_THREAD` | `0x0002` | Required for `CreateRemoteThread`. |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | Read process info (PEB, image base, etc). |
| `PROCESS_DUP_HANDLE` | `0x0040` | Duplicate handles out of the process. |

---

### Token Access Rights

Used as `DesiredAccess` when calling `OpenProcessToken` or `DuplicateTokenEx`.

| Constant | Value | Description |
|---|---|---|
| `TOKEN_ALL_ACCESS` | `0x000F01FF` | Full token access. |
| `TOKEN_QUERY` | `0x0008` | Read token information. |
| `TOKEN_IMPERSONATE` | `0x0004` | Use the token for impersonation. |
| `TOKEN_DUPLICATE` | `0x0002` | Duplicate the token. |
| `TOKEN_ASSIGN_PRIMARY` | `0x0001` | Assign as primary token when spawning a process. |
| `TOKEN_ADJUST_PRIVILEGES` | `0x0020` | Enable or disable privileges. |

---

### Memory Allocation Types

Used as `flAllocationType` in `VirtualAlloc` / `VirtualAllocEx`.

| Constant | Value | Description |
|---|---|---|
| `MEM_COMMIT` | `0x1000` | Commit physical storage for the region. |
| `MEM_RESERVE` | `0x2000` | Reserve address space without committing storage. |
| `MEM_RELEASE` | `0x8000` | Release a region. Used with `VirtualFree`. |

---

### Page Protection Flags

Used as `flProtect` in allocation and protection calls.

| Constant | Value | Description |
|---|---|---|
| `PAGE_EXECUTE_READWRITE` | `0x40` | Allocate as RWX. Readable, writable, and executable. |
| `PAGE_EXECUTE_READ` | `0x20` | Readable and executable. Flip to this after writing shellcode. |
| `PAGE_READWRITE` | `0x04` | Read/write only. Default for data. |
| `PAGE_NOACCESS` | `0x01` | No access. Will trigger an access violation on any touch. |

---

### Process Creation Flags

Used as `dwCreationFlags` in `CreateProcess` / `CreateProcessWithTokenW`.

| Constant | Value | Description |
|---|---|---|
| `CREATE_SUSPENDED` | `0x00000004` | Start the process with its main thread suspended. |
| `CREATE_NO_WINDOW` | `0x08000000` | Don't create a console window. |
| `EXTENDED_STARTUPINFO_PRESENT` | `0x00080000` | `lpStartupInfo` points to a `STARTUPINFOEX` structure. |

---

### Misc Constants

| Constant | Value | Description |
|---|---|---|
| `SE_PRIVILEGE_ENABLED` | `0x00000002` | Flag to enable a privilege in `AdjustTokenPrivileges`. |
| `SecurityImpersonation` | `2` | Impersonation level for `DuplicateTokenEx`. |
| `TokenPrimary` | `1` | Produce a primary token (for `CreateProcessWithTokenW`). |
| `TokenImpersonation` | `2` | Produce an impersonation token. |
| `DUPLICATE_SAME_ACCESS` | `0x2` | Preserve access rights when duplicating a handle. |
| `STARTF_USESTDHANDLES` | `0x100` | `STARTUPINFO.hStdInput/Output/Error` fields are valid. |

---

## Structs

### `PROCESS_INFORMATION`

Filled by `CreateProcess`. Contains handles and IDs for the new process and its primary thread.

| Field | Type | Description |
|---|---|---|
| `hProcess` | `IntPtr` | Handle to the new process. |
| `hThread` | `IntPtr` | Handle to the primary thread. |
| `dwProcessId` | `uint` | PID of the new process. |
| `dwThreadId` | `uint` | Thread ID of the primary thread. |

---

### `STARTUPINFO`

Passed to `CreateProcess`. At minimum, set `cb = Marshal.SizeOf<STARTUPINFO>()`.

---

### `MEMORY_BASIC_INFORMATION`

Filled by `VirtualQueryEx`. Describes the state and protection of a memory region.

| Field | Type | Description |
|---|---|---|
| `BaseAddress` | `IntPtr` | Start of the region. |
| `RegionSize` | `IntPtr` | Size in bytes. |
| `State` | `uint` | `0x1000` = committed, `0x2000` = reserved, `0x10000` = free. |
| `Protect` | `uint` | Current page protection. |
| `Type` | `uint` | `0x20000` = private, `0x40000` = mapped, `0x1000000` = image. |

---

## Process Methods

### `OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId)`

Opens a handle to an existing process with the requested access rights. Returns `IntPtr.Zero` on failure.

```csharp
var hProc = Win32.OpenProcess(Win32.PROCESS_ALL_ACCESS, false, targetPid);
if (hProc == IntPtr.Zero)
    Console.WriteLine($"OpenProcess failed: {Marshal.GetLastWin32Error()}");
```

---

### `CloseHandle(IntPtr hObject)`

Closes an open handle. Call this for every handle you open — process, thread, or token — when you're done with it.

```csharp
Win32.CloseHandle(hProc);
```

---

### `GetCurrentProcess()`

Returns a pseudo-handle to the current process. Value is always `-1` cast to `IntPtr`. No need to close it.

```csharp
var hSelf = Win32.GetCurrentProcess();
```

---

### `GetCurrentProcessId()`

Returns the PID of the calling process.

```csharp
var pid = Win32.GetCurrentProcessId();
```

---

### `CreateProcess(...)`

Creates a new process and its primary thread. The `lpCommandLine` parameter is mandatory; `lpApplicationName` can be null if the executable path is embedded in the command line.

```csharp
var si = new Win32.STARTUPINFO { cb = (uint)Marshal.SizeOf<Win32.STARTUPINFO>() };
var sa = new Win32.SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<Win32.SECURITY_ATTRIBUTES>() };

Win32.CreateProcess(null, @"C:\Windows\System32\notepad.exe",
    ref sa, ref sa, false,
    Win32.CREATE_SUSPENDED | Win32.CREATE_NO_WINDOW,
    IntPtr.Zero, null, ref si, out var pi);
```

---

### `TerminateProcess(IntPtr hProcess, uint uExitCode)`

Terminates a process. Use `0` for a clean exit code or any non-zero value to signal failure.

```csharp
Win32.TerminateProcess(hProc, 1);
```

---

### `NtSuspendProcess(IntPtr ProcessHandle)` / `NtResumeProcess(IntPtr ProcessHandle)`

Suspend or resume all threads in a process at once. More thorough than suspending individual threads.

```csharp
Win32.NtSuspendProcess(hProc);
// do memory work
Win32.NtResumeProcess(hProc);
```

---

### `NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr ProcessInformation, uint ProcessInformationLength, out uint ReturnLength)`

Direct ntdll query. `ProcessInformationClass = 0` returns a `PROCESS_BASIC_INFORMATION` struct containing the PEB base address.

```csharp
var pbiSize = (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
var buf = Marshal.AllocHGlobal((int)pbiSize);
Win32.NtQueryInformationProcess(hProc, 0, buf, pbiSize, out _);
// Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(buf)
Marshal.FreeHGlobal(buf);
```

---

## Thread Methods

### `OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId)`

Opens a handle to a thread. Access flag `0x0020` is `THREAD_SET_CONTEXT` (needed for APC injection). `0x001FFFFF` is full access.

```csharp
var hThread = Win32.OpenThread(0x001FFFFF, false, threadId);
```

---

### `CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId)`

Creates a thread in a remote process starting at `lpStartAddress`. Pass `0` for `dwCreationFlags` to start immediately, or `CREATE_SUSPENDED` to start suspended.

```csharp
var hThread = Win32.CreateRemoteThread(hProc, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, out var tid);
```

---

### `QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData)`

Queues an APC to a thread. The APC runs when the thread enters an alertable wait state. Returns a non-zero value on success.

```csharp
Win32.QueueUserAPC(shellcodeAddr, hThread, IntPtr.Zero);
```

---

### `ResumeThread(IntPtr hThread)` / `SuspendThread(IntPtr hThread)`

Resume or suspend a single thread.

```csharp
Win32.SuspendThread(hThread);
// modify thread context
Win32.ResumeThread(hThread);
```

---

### `WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)`

Waits for an object to become signaled. Pass `0xFFFFFFFF` to wait indefinitely. Returns `0` when signaled.

```csharp
Win32.WaitForSingleObject(hThread, 0xFFFFFFFF);
```

---

## Memory Methods

### `VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)`

Allocates memory in the current process. Pass `IntPtr.Zero` for `lpAddress` to let the OS pick the base.

```csharp
var mem = Win32.VirtualAlloc(IntPtr.Zero, 0x1000, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
```

---

### `VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)`

Same as `VirtualAlloc` but targets a remote process.

```csharp
var remote = Win32.VirtualAllocEx(hProc, IntPtr.Zero, (uint)shellcode.Length,
    Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
```

---

### `VirtualFree(IntPtr lpAddress, int dwSize, uint dwFreeType)` / `VirtualFreeEx(...)`

Releases allocated memory. When `dwFreeType` is `MEM_RELEASE`, `dwSize` must be `0` — the OS frees the entire allocation.

```csharp
Win32.VirtualFree(mem, 0, Win32.MEM_RELEASE);
Win32.VirtualFreeEx(hProc, remote, 0, Win32.MEM_RELEASE);
```

---

### `VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect)` / `VirtualProtectEx(...)`

Changes the protection on a region. The old protection is written to `lpflOldProtect`. Standard pattern is to allocate RW, write your data, then flip to XR.

```csharp
Win32.VirtualProtect(mem, 0x1000, Win32.PAGE_EXECUTE_READ, out var oldProt);
```

---

### `ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead)` / `WriteProcessMemory(...)`

Read from or write to a remote process's virtual memory. Requires `PROCESS_VM_READ` / `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`.

```csharp
var buf = new byte[0x100];
Win32.ReadProcessMemory(hProc, targetAddr, buf, buf.Length, out var read);

Win32.WriteProcessMemory(hProc, remoteAddr, shellcode, shellcode.Length, out var written);
```

---

### `VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength)`

Queries memory region info at `lpAddress`. Walk address space by advancing by `mbi.RegionSize` each iteration. Returns `0` when past the end of the address space.

```csharp
var mbi = new Win32.MEMORY_BASIC_INFORMATION();
Win32.VirtualQueryEx(hProc, addr, out mbi, (uint)Marshal.SizeOf<Win32.MEMORY_BASIC_INFORMATION>());
```

---

### `GetSystemInfo(out SYSTEM_INFO lpSystemInfo)`

Returns system-level info including address space bounds, page size, and processor count. Use `lpMinimumApplicationAddress` and `lpMaximumApplicationAddress` as bounds for memory enumeration loops.

```csharp
Win32.GetSystemInfo(out var info);
Console.WriteLine($"Page size: {info.dwPageSize}");
```

---

### `DuplicateHandle(...)`

Duplicates a handle from one process into another. Use `DUPLICATE_SAME_ACCESS` to preserve the original access mask.

```csharp
Win32.DuplicateHandle(srcProc, srcHandle, Win32.GetCurrentProcess(), out var localHandle,
    0, false, Win32.DUPLICATE_SAME_ACCESS);
```

---

## Token Methods

### `OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle)`

Opens the primary token of a process. Always close the token handle when done.

```csharp
Win32.OpenProcessToken(hProc, Win32.TOKEN_DUPLICATE | Win32.TOKEN_QUERY, out var hToken);
```

---

### `DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken)`

Duplicates a token. Use `TokenImpersonation` + `SecurityImpersonation` for an impersonation token, or `TokenPrimary` + `SecurityImpersonation` for one you can use with `CreateProcessWithTokenW`.

```csharp
Win32.DuplicateTokenEx(hToken, Win32.TOKEN_ALL_ACCESS, IntPtr.Zero,
    Win32.SecurityImpersonation, Win32.TokenPrimary, out var hPrimary);
```

---

### `ImpersonateLoggedOnUser(IntPtr hToken)` / `RevertToSelf()`

Impersonates the security context of the token on the current thread. Call `RevertToSelf` to drop the impersonation.

```csharp
Win32.ImpersonateLoggedOnUser(hToken);
// operating as impersonated user
Win32.RevertToSelf();
```

---

### `LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken)`

Creates a token by authenticating with a username and password. `dwLogonType = 2` is interactive, `9` is `LOGON32_LOGON_NEW_CREDENTIALS` (useful for lateral movement — uses given creds only for network auth).

```csharp
Win32.LogonUser("jsmith", "CORP", "P@ssw0rd1", 9, 0, out var hToken);
```

---

### `CreateProcessWithTokenW(...)`

Spawns a process under a different token. Requires `SeImpersonatePrivilege`.

```csharp
Win32.CreateProcessWithTokenW(hToken, 0, null, "cmd.exe",
    Win32.CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out var pi);
```

---

### `AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, ...)`

Enable or disable privileges on a token. Note that this call succeeds even if the privilege isn't available — check `Marshal.GetLastWin32Error()` for `ERROR_NOT_ALL_ASSIGNED` (1300) to confirm the privilege was actually enabled.

---

### `LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid)`

Looks up the LUID for a privilege name. Pass `null` for `lpSystemName` to query the local system.

```csharp
Win32.LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid);
```

---

## Managed Helpers

### `EnablePrivilege(IntPtr tokenHandle, string privilege)`

Combines `LookupPrivilegeValue` and `AdjustTokenPrivileges` into one call. Returns `true` if the privilege was enabled.

```csharp
Win32.OpenProcessToken(Win32.GetCurrentProcess(), Win32.TOKEN_ADJUST_PRIVILEGES, out var hToken);
Win32.EnablePrivilege(hToken, "SeDebugPrivilege");
Win32.CloseHandle(hToken);
```

---

### `EnableCurrentProcessPrivilege(string privilege)`

Opens the current process token, enables the privilege, and closes the token. One-liner convenience method.

```csharp
Win32.EnableCurrentProcessPrivilege("SeDebugPrivilege");
Win32.EnableCurrentProcessPrivilege("SeImpersonatePrivilege");
```

---

### `ReadMemory(IntPtr hProcess, IntPtr address, int size)`

Wrapper around `ReadProcessMemory` that allocates the buffer for you and returns it.

```csharp
var bytes = Win32.ReadMemory(hProc, pebAddress, 0x200);
```

---

### `WriteMemory(IntPtr hProcess, IntPtr address, byte[] data)`

Wrapper around `WriteProcessMemory`. Returns `true` on success.

```csharp
Win32.WriteMemory(hProc, remoteAddr, shellcode);
```

---

### `EnumerateMemoryRegions(IntPtr hProcess)`

Walks the full virtual address space of a process using `VirtualQueryEx` and returns all `MEMORY_BASIC_INFORMATION` entries as a list. Uses `GetSystemInfo` to determine the valid address range.

```csharp
var hProc = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION, false, targetPid);
var regions = Win32.EnumerateMemoryRegions(hProc);

var rwxRegions = regions.Where(r =>
    r.State == 0x1000 &&
    r.Protect == Win32.PAGE_EXECUTE_READWRITE).ToList();

Console.WriteLine($"Found {rwxRegions.Count} RWX regions");
Win32.CloseHandle(hProc);
```
