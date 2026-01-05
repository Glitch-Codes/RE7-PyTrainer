import utility

class NoReload:
    def __init__(self, process, proc_handle, base_address):
        self.process = process
        self.proc_handle = proc_handle
        self.base_address = base_address
        self.enabled = False
        
    def enable(self):
        """Enable no reload by replacing ammo decrement instruction"""
        if self.enabled:
            return True
            
        # Get addresses
        self.ammo_op_code_addr = self.base_address + 0x1945FF7
        
        if not self.ammo_op_code_addr:
            return False
        
        print(f"Found Ammo Decrement opcode at: {hex(self.ammo_op_code_addr)}")
        
        # Patch the opcode to NOPs
        try:
            # NOP out the instruction (replace with 3 NOPs: 90 90 90 using utility function nopBytes)
            utility.nopBytes(self.proc_handle, self.ammo_op_code_addr, 3)
            self.enabled = True
            print("No reload enabled!")
            return True
        except Exception as e:
            print(f"Failed to enable no reload: {e}")
            if self.newmem:
                utility.freeMemory(self.proc_handle, self.newmem)
            return False
    
    def disable(self):
        """Disable no reload by restoring original bytes"""
        if not self.enabled:
            return
        
        # Restore original opcode
        if self.ammo_op_code_addr:
            utility.patchOpcodes(self.proc_handle, "mov [rbx+0x14],eax", self.ammo_op_code_addr)

        self.enabled = False
        print("No reload disabled!")