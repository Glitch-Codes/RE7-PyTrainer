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
        
        # Allocate memory for code cave
        self.newmem = utility.allocMemory(self.proc_handle, 0x100)
        if not self.newmem:
            return False
        
        print(f"Allocated code cave at: {hex(self.newmem)}")

        # Build the assembly code for the code cave
        return_addr = self.no_spread_addr + 6
        
        # Use placeholder method for addresses
        asm_code = """
            push rax
            mov rax, 0xDEADBEEFDEADBEEF
            movss xmm13, dword ptr [rax]
            pop rax
            mov rax, 0xCAFEBABECAFEBABE
            jmp rax
        """

        # Assemble the code cave
        try:
            code_bytes = utility.asmToBytes(asm_code.replace("\n", "; "), self.newmem)
            
            # Replace placeholders with actual addresses
            code_hex = ''.join(f'{b:02x}' for b in code_bytes)
            
            # Replace 0xDEADBEEFDEADBEEF with actual spread value address
            spread_addr = self.newmem + 0x50
            # Convert to little-endian hex string - ensure it's treated as unsigned
            spread_addr = spread_addr & 0xFFFFFFFFFFFFFFFF  # Ensure unsigned 64-bit
            spread_addr_bytes = spread_addr.to_bytes(8, 'little', signed=False)
            spread_addr_hex = ''.join(f'{b:02x}' for b in spread_addr_bytes)
            code_hex = code_hex.replace('efbeaddeefbeadde', spread_addr_hex)
            
            # Replace 0xCAFEBABECAFEBABE with actual return address
            return_addr = return_addr & 0xFFFFFFFFFFFFFFFF  # Ensure unsigned 64-bit
            return_addr_bytes = return_addr.to_bytes(8, 'little', signed=False)
            return_addr_hex = ''.join(f'{b:02x}' for b in return_addr_bytes)
            code_hex = code_hex.replace('bebafecabebafeca', return_addr_hex)
            
            # Write code cave to allocated memory
            utility.patchBytes(self.proc_handle, code_hex, self.newmem, len(code_hex) // 2)
            
            # Write the spread value to the allocated memory at offset +0x50
            spread_value = 0.0001
            spread_bytes = struct.pack('<f', spread_value)  # Little-endian float
            spread_hex = ''.join(f'{b:02x}' for b in spread_bytes)
            utility.patchBytes(self.proc_handle, spread_hex, self.newmem + 0x50, 4)
            
            # Create jump from original location to code cave
            jmp_offset = self.newmem - (self.no_spread_addr + 5)
            
            # Convert offset to signed 32-bit integer bytes
            if jmp_offset < 0:
                # Handle negative offset (two's complement)
                jmp_offset_bytes = (jmp_offset & 0xFFFFFFFF).to_bytes(4, 'little')
            else:
                jmp_offset_bytes = jmp_offset.to_bytes(4, 'little')
            
            jmp_bytes = bytes([0xE9]) + jmp_offset_bytes + bytes([0x90])  # E9 = JMP, 90 = NOP
            
            # Write the hook
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in jmp_bytes),
                             self.no_spread_addr, 6)
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

