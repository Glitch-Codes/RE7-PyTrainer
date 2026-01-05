import utility

class InfiniteAmmo:
    def __init__(self, process, proc_handle, base_address):
        self.process = process
        self.proc_handle = proc_handle
        self.base_address = base_address
        self.enabled = False
        
    def enable(self):
        """Enable infinite ammo by replacing the check for current ammo instruction"""
        if self.enabled:
            return True
            
        # Get addresses
        self.ammo_op_code_addr = self.base_address + 0x1FDCC3
        
        if not self.ammo_op_code_addr:
            return False
        
        print(f"Found Ammo Decrement opcode at: {hex(self.ammo_op_code_addr)}")

        # Save original bytes
        self.original_bytes = self.process.read_bytes(self.ammo_op_code_addr, 3)
        print(f"Original bytes: {self.original_bytes.hex()}")

        newmem = utility.findCodeCave(self.process, self.ammo_op_code_addr, len(self.original_bytes), 5)
        
        # Patch the opcode to always set ammo available
        try:
            utility.patchOpcodes(self.proc_handle, "mov al,01", self.ammo_op_code_addr)
            self.enabled = True
            print("Infinite ammo enabled!")
            return True
        except Exception as e:
            print(f"Failed to enable infinite ammo: {e}")
            if self.newmem:
                utility.freeMemory(self.proc_handle, self.newmem)
            return False
    
    def disable(self):
        """Disable infinite ammo by restoring original bytes"""
        if not self.enabled:
            return
        
        # Restore original opcode
        if self.ammo_op_code_addr:
            utility.patchOpcodes(self.proc_handle, "setne al", self.ammo_op_code_addr)

        self.enabled = False
        print("Infinite ammo disabled!")