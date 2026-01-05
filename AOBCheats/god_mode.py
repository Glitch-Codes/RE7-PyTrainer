import utility

class GodMode:
    def __init__(self, process, proc_handle, base_address):
        self.process = process
        self.proc_handle = proc_handle
        self.base_address = base_address
        self.enabled = False
        
        self.god_mode_addr = None
        self.newmem = None
        self.original_bytes = None
        self.player_addr = None
        self.one_hit_kill = False
        
    def enable(self):
        """Enable god mode by injecting code cave"""
        if self.enabled:
            return True
            
        # AOB scan for the health instruction
        # Pattern: F3 0F 11 52 14 (movss [rdx+14],xmm2)
        pattern = "F3 0F 11 52 14"
        self.god_mode_addr = utility.aobScan(self.process, pattern, "re7.exe")
        
        if not self.god_mode_addr:
            return False
        
        print(f"Found GodMode at: {hex(self.god_mode_addr)}")
        
        # Save original bytes
        self.original_bytes = self.process.read_bytes(self.god_mode_addr, 5)
        
        # Allocate memory for code cave
        self.newmem = utility.allocMemory(self.proc_handle, 0x1000)
        if not self.newmem:
            return False
        
        print(f"Allocated code cave at: {hex(self.newmem)}")
        
        # Build the assembly code for the code cave
        return_addr = self.god_mode_addr + 5
        
        # Calculate RIP-relative offsets for data storage
        # Data will be stored at the end of the code cave
        data_offset = 0x100
        
        asm_code = f"""
            push rax
            
            // Check if this is the player (compare against a known player signature)
            cmp qword ptr [rsi+0x50], 0x01
            je player_health
            
            // Check if one hit kill is enabled
            lea rax, [rip+{data_offset-20}]
            cmp byte ptr [rax], 0
            pop rax
            je original_code
            
            // One hit kill logic - set enemy health to very low value
            push rax
            lea rax, [rip+{data_offset-32}]
            movss xmm2, dword ptr [rax]
            pop rax
            jmp original_code
            
        player_health:
            pop rax
            movss xmm2, dword ptr [rdx+0x10]
            
        original_code:
            movss dword ptr [rdx+0x14], xmm2
            jmp qword ptr [rip+{data_offset-48}]
        """
        
        # Assemble the code cave
        try:
            code_bytes = utility.asmToBytes(asm_code.replace("\n", "; "), self.newmem)
            
            # Write code cave to allocated memory
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in code_bytes), 
                             self.newmem, len(code_bytes))
            
            # Write data section
            # Offset +0x100: one hit kill flag (1 byte)
            self.process.write_uchar(self.newmem + 0x100, 0)
            
            # Offset +0x104: low health value for enemies (float: 1.0 = 0x3F800000)
            self.process.write_float(self.newmem + 0x104, 1.0)
            
            # Offset +0x108: return address (8 bytes)
            self.process.write_longlong(self.newmem + 0x108, return_addr)
            
            # Create jump from original location to code cave
            jmp_offset = self.newmem - (self.god_mode_addr + 5)
            jmp_bytes = [0xE9] + list(jmp_offset.to_bytes(4, 'little', signed=True))
            
            # Write the hook
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in jmp_bytes),
                             self.god_mode_addr, 5)
            
            self.enabled = True
            print("God mode enabled!")
            return True
            
        except Exception as e:
            print(f"Failed to enable god mode: {e}")
            if self.newmem:
                utility.freeMemory(self.proc_handle, self.newmem)
            return False
    
    def disable(self):
        """Disable god mode by restoring original bytes"""
        if not self.enabled:
            return
        
        # Restore original bytes
        if self.original_bytes and self.god_mode_addr:
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in self.original_bytes), self.god_mode_addr, len(self.original_bytes))
        
        # Free allocated memory
        if self.newmem:
            utility.freeMemory(self.proc_handle, self.newmem)
            self.newmem = None
        
        self.enabled = False
        print("God mode disabled!")
    
    def set_one_hit_kill(self, enabled):
        """Enable/disable one hit kill for enemies"""
        if not self.enabled or not self.newmem:
            return False
        
        self.one_hit_kill = enabled
        value = 1 if enabled else 0
        
        # Write the one hit kill flag to offset +0x100 in code cave
        self.process.write_uchar(self.newmem + 0x100, value)
        return True
