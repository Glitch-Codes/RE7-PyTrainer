import ctypes
from ctypes import wintypes
from consts import *
import pymem
import pymem.process

kernel32 = ctypes.windll.kernel32

def getProcId(processName):
    procId = None
    hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    if (hSnap != INVALID_HANDLE_VALUE):
        procEntry = PROCESSENTRY32()
        procEntry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if (kernel32.Process32First(hSnap, ctypes.byref(procEntry))):
            def processCmp(procEntry):
                if (procEntry.szExeFile.decode("utf-8") == processName):
                    nonlocal procId
                    procId = int(procEntry.th32ProcessID)
                
            processCmp(procEntry)
            while (kernel32.Process32Next(hSnap, ctypes.byref(procEntry))):
                processCmp(procEntry)
        
    kernel32.CloseHandle(hSnap)
    return(procId) 

def getModuleBaseAddress(pid, moduleName):
    baseAddress = None
    hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)

    if (hSnap != INVALID_HANDLE_VALUE):
        modEntry = MODULEENTRY32()
        modEntry.dwSize = ctypes.sizeof(MODULEENTRY32)

        if (kernel32.Module32First(hSnap, ctypes.byref(modEntry))):
            def moduleCmp(modEntry):
                if (modEntry.szModule.decode("utf-8") == moduleName) :
                    nonlocal baseAddress
                    baseAddress = int(hex(ctypes.addressof(modEntry.modBaseAddr.contents)), 16)
                
            moduleCmp(modEntry)
            while (kernel32.Module32Next(hSnap, ctypes.byref(modEntry))):
                moduleCmp(modEntry)
        
    kernel32.CloseHandle(hSnap)
    return(baseAddress) 

def getPointerAddr(process, base, offsets):
    try:
        addr = process.read_longlong(base)  # Read 64-bit pointer
        print(f"Base read: {hex(base)} -> {hex(addr)}")
    except Exception as e:
        print(f"Failed to read base address {hex(base)}: {e}")
        raise
    
    for i, offset in enumerate(offsets):
        print(f"Processing offset {i}: {hex(offset)}")
        if i == len(offsets) - 1:
            # Last offset: just add it, don't dereference
            addr = addr + offset
            print(f"Final offset: {hex(addr - offset)} + {hex(offset)} = {hex(addr)}")
        else:
            # Intermediate offsets: add and dereference
            try:
                prev_addr = addr
                addr = process.read_longlong(addr + offset)  # Read 64-bit pointer
                print(f"Offset {i}: {hex(prev_addr)} + {hex(offset)} = {hex(prev_addr + offset)} -> {hex(addr)}")
            except Exception as e:
                print(f"Failed to read at offset {i} ({hex(offset)}), address {hex(prev_addr + offset)}: {e}")
                raise
    return addr

def findDMAAddy(hProc, base, offsets, arch=64):
    size = 8
    if (arch == 32): size = 4
    address = ctypes.c_uint64(base)

    for offset in offsets:
        kernel32.ReadProcessMemory(hProc, address, ctypes.byref(address), size, 0)
        address = ctypes.c_uint64(address.value + offset)
    
    return (address.value)

def patchBytes(handle, src, destination, size):
    src = bytes.fromhex(src)
    size = ctypes.c_size_t(size)
    destination = ctypes.c_ulonglong(destination)
    oldProtect = ctypes.wintypes.DWORD()

    kernel32.VirtualProtectEx(handle, destination, size, PAGE_EXECUTE_READWRITE, ctypes.byref(oldProtect))
    kernel32.WriteProcessMemory(handle, destination, src, size, None)
    kernel32.VirtualProtectEx(handle, destination, size, oldProtect, ctypes.byref(oldProtect))

def aobScan(process, pattern, module_name=None):
    """
    Array of Bytes scan. Pattern uses ?? for wildcards.
    Example: aobScan(process, "F3 0F 11 52 14")
    Example: aobScan(process, "F3 ?? ?? ?? 14")
    Returns the address of the first match or None
    """
    # Convert pattern string to regex pattern
    pattern_parts = pattern.replace(" ", "").upper()
    pattern_bytes = []
    i = 0
    while i < len(pattern_parts):
        if i + 1 < len(pattern_parts):
            byte_str = pattern_parts[i:i+2]
            if byte_str == "XX" or byte_str == "??":
                pattern_bytes.append(None)  # Wildcard
            else:
                pattern_bytes.append(int(byte_str, 16))
            i += 2
        else:
            i += 1
    
    # Get module info
    if module_name:
        module = pymem.process.module_from_name(process.process_handle, module_name)
        start_address = module.lpBaseOfDll
        end_address = start_address + module.SizeOfImage
    else:
        start_address = process.base_address
        end_address = start_address + 0x10000000  # 256 MB scan range
    
    # Scan memory
    chunk_size = 0x10000  # 64KB chunks
    for addr in range(start_address, end_address, chunk_size):
        try:
            data = process.read_bytes(addr, min(chunk_size, end_address - addr))
            
            # Search for pattern
            for offset in range(len(data) - len(pattern_bytes) + 1):
                match = True
                for i, pattern_byte in enumerate(pattern_bytes):
                    if pattern_byte is not None and data[offset + i] != pattern_byte:
                        match = False
                        break
                if match:
                    return addr + offset
        except:
            continue
    
    return None

def allocMemory(handle, size, preferred_address=None):
    """Allocate executable memory, optionally near a preferred address"""
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    
    addr = kernel32.VirtualAllocEx(
        handle,
        ctypes.c_void_p(preferred_address) if preferred_address else None,
        ctypes.c_size_t(size),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if addr == 0 or addr is None:
        return None  # Return None instead of raising exception
    
    return addr

def freeMemory(handle, address):
    """Free allocated memory"""
    MEM_RELEASE = 0x8000
    if address:
        kernel32.VirtualFreeEx(handle, ctypes.c_void_p(address), 0, MEM_RELEASE)

def asmToBytes(asm_code, address=0):
    """
    Convert assembly instruction string to bytes.
    Example: asmToBytes("mov [rbx+14],eax") returns [0x89, 0x43, 0x14]
    Requires keystone-engine: pip install keystone-engine
    """
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_64
        
        # Initialize keystone for x64
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        
        # Assemble the instruction at the specified address for relative jumps
        encoding, count = ks.asm(asm_code, address)
        
        if encoding is None:
            raise Exception(f"Failed to assemble: {asm_code}")
        
        return encoding
    except ImportError:
        raise ImportError("keystone-engine is required. Install it with: pip install keystone-engine")

def patchOpcodes(handle, opcodes, destination):
    """
    Patch memory with opcodes. Accepts opcodes as a list of integers, hex strings, or assembly string.
    Example: patchOpcodes(handle, [0x89, 0x43, 0x14], address)
    Example: patchOpcodes(handle, ["89", "43", "14"], address)
    Example: patchOpcodes(handle, "mov [rbx+14],eax", address)
    """
    if isinstance(opcodes, str) and any(x in opcodes for x in [' ', '[', ']', ',']):
        # Looks like assembly instruction
        opcodes = asmToBytes(opcodes)
    
    if isinstance(opcodes, list):
        # Convert list of integers or strings to hex string
        hex_string = ""
        for opcode in opcodes:
            if isinstance(opcode, int):
                hex_string += f"{opcode:02x}"
            else:
                hex_string += opcode.replace("0x", "").replace(" ", "")
    else:
        # Assume it's already a hex string
        hex_string = opcodes.replace("0x", "").replace(" ", "")
    
    size = len(hex_string) // 2
    patchBytes(handle, hex_string, destination, size)

def nopBytes(handle, destination, size):  
    hex_string = ""
    for i in range(size):
        hex_string += "90"
    patchBytes(handle, hex_string, destination, size)

def findCodeCave(process, opcode_addr, original_byte_size, jump_back_size):
    # Search for writable memory within 2GB that we can use for our code cave
    # We need space for: original instruction (6 bytes) + jump back (5 bytes) = 11 bytes minimum
    newmem = None
    
    hook_rip = opcode_addr + original_byte_size
    print(f"Searching for code cave +/- 2GB of {hex(hook_rip)}")
    
    # Search in the game's module for writable memory
    search_ranges = [
        (opcode_addr - 0x10000000, opcode_addr),  # 256MB before
        (opcode_addr, opcode_addr + 0x10000000),  # 256MB after
    ]
    
    for start, end in search_ranges:
        if newmem:
            break
        
        # Search in 64KB chunks
        for addr in range(start, end, 0x10000):
            try:
                # Try to read 32 bytes
                data = process.read_bytes(addr, 32)
                
                # Look for at least 16 consecutive zeros (indicating unused space)
                for i in range(len(data) - 15):
                    if data[i:i+16] == b'\x00' * 16:
                        potential_addr = addr + i
                        
                        # Check if we can jump TO it from the hook (5-byte jump)
                        jmp_to_offset = potential_addr - (opcode_addr + jump_back_size)
                        # Check if we can jump BACK from it to after the hook
                        jmp_back_offset = (opcode_addr + original_byte_size) - (potential_addr + original_byte_size + jump_back_size)
                        
                        if (-2147483648 <= jmp_to_offset <= 2147483647 and 
                            -2147483648 <= jmp_back_offset <= 2147483647):
                            # Try to write to it to verify it's writable
                            try:
                                test_bytes = b'\x00' * 16
                                patchBytes(process, ''.join(f'{b:02x}' for b in test_bytes), potential_addr, 16)
                                newmem = potential_addr
                                print(f"Found code cave at: {hex(newmem)}")
                                print(f"  Jump to offset: {jmp_to_offset}")
                                print(f"  Jump back offset: {jmp_back_offset}")
                                break
                            except:
                                continue
                
                if newmem:
                    break
            except:
                continue
    
    if not newmem:
        print("Failed to find suitable code cave within 2GB")
        return False