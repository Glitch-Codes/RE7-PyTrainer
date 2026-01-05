import utility
import struct

class NoSpread:
    def __init__(self, process, proc_handle, base_address):
        self.process = process
        self.proc_handle = proc_handle
        self.base_address = base_address
        self.enabled = False
        
        self.no_spread_addr = None
        self.newmem = None
        self.original_bytes = None
        
    def enable(self):
        """Enable no spread by replacing weapon spread instruction"""
        if self.enabled:
            return True
            
        # AOB scan for the spread instruction
        # Pattern: F3 44 0F 10 68 38 (movss xmm13,[rax+38])
        pattern = "F3 44 0F 10 68 38"
        self.no_spread_addr = utility.aobScan(self.process, pattern, "re7.exe")
        
        if not self.no_spread_addr:
            return False
        
        print(f"Found NoSpread at: {hex(self.no_spread_addr)}")
        
        # Save original bytes (6 bytes)
        self.original_bytes = self.process.read_bytes(self.no_spread_addr, 6)
        print(f"Original bytes: {self.original_bytes.hex()}")
        
        # Allocate memory for code cave (no distance restriction with absolute jumps)
        self.newmem = utility.allocMemory(self.proc_handle, 0x1000, None)
        if not self.newmem:
            print("Failed to allocate memory")
            return False
        
        print(f"Allocated space for No Spread at: {hex(self.newmem)}")

        # Assemble the code cave
        try:
            # Write original instruction to code cave
            original_hex = ''.join(f'{b:02x}' for b in self.original_bytes)
            utility.patchBytes(self.proc_handle, original_hex, self.newmem, len(self.original_bytes))
            
            # Write an absolute jump back to original code (no distance restriction)
            # FF 25 00 00 00 00 [8-byte address] = jmp qword ptr [rip+0]
            return_addr = self.no_spread_addr + 6  # Address after our hook
            jmp_back_bytes = bytes([0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]) + return_addr.to_bytes(8, 'little')
            jmp_back_hex = ''.join(f'{b:02x}' for b in jmp_back_bytes)
            utility.patchBytes(self.proc_handle, jmp_back_hex, self.newmem + len(self.original_bytes), 14)
            
            # Create jump from original location to code cave
            jmp_offset = self.newmem - (self.no_spread_addr + 5)
            
            # Check if we can use a relative jump (5 bytes + 1 NOP)
            if -2147483648 <= jmp_offset <= 2147483647:
                jmp_offset_bytes = jmp_offset.to_bytes(4, 'little', signed=True)
                jmp_bytes = bytes([0xE9]) + jmp_offset_bytes + bytes([0x90])  # E9 = JMP, 90 = NOP
                utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in jmp_bytes), self.no_spread_addr, 6)
            else:
                # Distance too large for relative jump
                print(f"Jump offset too large: {jmp_offset}. Need different hooking strategy.")
                utility.freeMemory(self.proc_handle, self.newmem)
                return False
            
            self.enabled = True
            print("No spread enabled!")
            return True
        except Exception as e:
            print(f"Failed to enable no spread: {e}")
            if self.newmem:
                utility.freeMemory(self.proc_handle, self.newmem)
            return False
    
    def disable(self):
        """Disable no spread by restoring original bytes"""
        if not self.enabled:
            return
        
        # Restore original bytes
        if self.original_bytes and self.no_spread_addr:
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in self.original_bytes), self.no_spread_addr, len(self.original_bytes))
        
        # Free allocated memory
        if self.newmem:
            utility.freeMemory(self.proc_handle, self.newmem)
            self.newmem = None
        
        self.enabled = False
        print("No spread disabled!")
    
    def set_spread_value(self, value):
        """Set the spread value (default: 0.0001, higher = more spread)"""
        if not self.enabled or not self.newmem:
            return False
        
        # Write the spread value to offset +0x50 in code cave
        spread_bytes = struct.pack('<f', value)  # Little-endian float
        spread_hex = ''.join(f'{b:02x}' for b in spread_bytes)
        utility.patchBytes(self.proc_handle, spread_hex, self.newmem + 0x50, 4)
        return True

