1. Allocates memory in the target process using `NtCreateSection`/`NtMapViewOfSection`
2. Manually writes the PE headers and sections
3. Fixes relocations if the base address differs
4. Resolves imports by manually calling `GetProcAddress`
5. Executes TLS callbacks
6. Registers SEH exception handlers (x64 only)
7. Calls the DLL's entry point (`DllMain`)

## Key Features

### Evasion Techniques

- **Section-Based Memory Allocation**: Uses `NtCreateSection`/`NtMapViewOfSection` instead of `VirtualAllocEx` (harder to detect)
- **PE Header Wiping**: Erases DOS/NT headers after injection to hide the DLL signature
- **PEB Module List Spoofing**: Adds a fake entry as `dbghelp.dll` to disguise the injected module
- **Proper Memory Protections**: Sets correct RWX/RX/RW permissions per section based on characteristics
- **Cleanup**: Unmaps shellcode and data sections after execution

###  Injection Process

1. **Validation**: Checks DOS/NT signatures and architecture compatibility
2. **Memory Allocation**: Creates RWX memory sections in target process
3. **PE Writing**: Writes headers and all sections to target memory
4. **Relocation Fixing**: Adjusts addresses if DLL isn't loaded at preferred base
5. **Import Resolution**: Manually resolves all imported functions
6. **Shellcode Execution**: Runs loader shellcode via remote thread
7. **Cleanup & Stealth**: Erases headers, adds PEB entry, sets protections, unmaps temporary sections

## Important Note

**Thread Execution Method**: This implementation uses `CreateRemoteThread` for testing and demonstration purposes only. For production or stealth scenarios, you should replace it with more advanced techniques.

Developed by **ODIN**  
GitHub: [Odin-XD](https://github.com/Odin-XD)

