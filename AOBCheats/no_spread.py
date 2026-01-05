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
        self.trampoline = None
        self.original_bytes = None
        
    def enable(self):
        """Enable no spread by replacing weapon spread instruction"""
        if self.enabled:
            return True
            
        # AOB scan for the spread instruction
        # Pattern: F3 44 0F 10 68 38 (movss xmm13,[rax+38]) + F3 44 0F 11 54 24 28 (movss [rsp+28],xmm10)
        #pattern = "F3 44 0F 10 68 38 F3 44 0F 11 54"
        #self.no_spread_addr = utility.aobScan(self.process, pattern, "re7.exe")

        # Get address by pointer
        self.no_spread_addr = self.base_address + 0x18F4416
        
        if not self.no_spread_addr:
            return False
        
        print(f"Found NoSpread at: {hex(self.no_spread_addr)}")
        
        # Save original bytes (6 bytes)
        self.original_bytes = self.process.read_bytes(self.no_spread_addr, 6)
        print(f"Original bytes: {self.original_bytes.hex()}")
        
        # Search for writable memory within 2GB that we can use for our code cave
        # We need space for: original instruction (6 bytes) + jump back (5 bytes) = 11 bytes minimum
        self.newmem = None
        
        hook_rip = self.no_spread_addr + len(self.original_bytes)
        print(f"Searching for code cave within 2GB of {hex(hook_rip)}")
        
        # Search in the game's module for writable memory
        search_ranges = [
            (self.no_spread_addr - 0x10000000, self.no_spread_addr),  # 256MB before
            (self.no_spread_addr, self.no_spread_addr + 0x10000000),  # 256MB after
        ]
        
        for start, end in search_ranges:
            if self.newmem:
                break
            
            # Search in 64KB chunks
            for addr in range(start, end, 0x10000):
                try:
                    # Try to read 32 bytes
                    data = self.process.read_bytes(addr, 32)
                    
                    # Look for at least 16 consecutive zeros (indicating unused space)
                    for i in range(len(data) - 15):
                        if data[i:i+16] == b'\x00' * 16:
                            potential_addr = addr + i
                            
                            # Check if we can jump TO it from the hook (5-byte jump)
                            jmp_to_offset = potential_addr - (self.no_spread_addr + 5)
                            # Check if we can jump BACK from it to after the hook
                            jmp_back_offset = (self.no_spread_addr + 6) - (potential_addr + 6 + 5)
                            
                            if (-2147483648 <= jmp_to_offset <= 2147483647 and 
                                -2147483648 <= jmp_back_offset <= 2147483647):
                                # Try to write to it to verify it's writable
                                try:
                                    test_bytes = b'\x00' * 16
                                    utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in test_bytes), potential_addr, 16)
                                    self.newmem = potential_addr
                                    print(f"Found code cave at: {hex(self.newmem)}")
                                    print(f"  Jump to offset: {jmp_to_offset}")
                                    print(f"  Jump back offset: {jmp_back_offset}")
                                    break
                                except:
                                    continue
                    
                    if self.newmem:
                        break
                except:
                    continue
        
        if not self.newmem:
            print("Failed to find suitable code cave within 2GB")
            return False
        
        try:
            # Build code cave: store 0.0001 float, load it into xmm13, then jump back
            
            # Store the spread value as a float
            spread_value = 0.0001
            spread_bytes = struct.pack('<f', spread_value)
            
            # Use RIP-relative addressing to load the float
            # The instruction is at cave+4, and is 9 bytes long
            # So RIP after the instruction = cave+4+9 = cave+13
            # Float is at cave+0
            # Offset = cave+0 - cave+13 = -13
            instruction_addr = self.newmem + 4
            rip_after_instruction = instruction_addr + 9
            rip_offset = self.newmem - rip_after_instruction
            
            print(f"Float at: {hex(self.newmem)}")
            print(f"Instruction at: {hex(instruction_addr)}")
            print(f"RIP after instruction: {hex(rip_after_instruction)}")
            print(f"RIP offset: {rip_offset} (0x{rip_offset & 0xFFFFFFFF:08x})")
            
            rip_offset_bytes = rip_offset.to_bytes(4, 'little', signed=True)
            load_instruction = bytes([0xF3, 0x44, 0x0F, 0x10, 0x2D]) + rip_offset_bytes
            
            print(f"Load instruction bytes: {load_instruction.hex()}")
            print(f"  Expected: f3440f102d + offset")
            print(f"  Offset bytes: {rip_offset_bytes.hex()}")
            
            # Jump back to address after hook
            return_addr = self.no_spread_addr + 6
            cave_end = self.newmem + 4 + 9 + 5  # float + instruction + jump
            jmp_back_offset = return_addr - cave_end
            jmp_back_bytes = bytes([0xE9]) + jmp_back_offset.to_bytes(4, 'little', signed=True)
            
            # Assemble cave code: float + load instruction + jump back
            cave_code = spread_bytes + load_instruction + jmp_back_bytes
            
            print(f"Writing {len(cave_code)} bytes to code cave: {cave_code.hex()}")
            print(f"  Spread bytes (offset 0-3): {spread_bytes.hex()}")
            print(f"  Load instruction (offset 4-12): {load_instruction.hex()}")
            print(f"  Jump back (offset 13-17): {jmp_back_bytes.hex()}")
            print(f"  Spread value: {spread_value}")
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in cave_code), self.newmem, len(cave_code))
            
            # Verify what was written
            verify = self.process.read_bytes(self.newmem, len(cave_code))
            print(f"Verified bytes written: {verify.hex()}")
            if verify != cave_code:
                print(f"WARNING: Bytes mismatch!")
                print(f"  Expected: {cave_code.hex()}")
                print(f"  Got:      {verify.hex()}")
            
            # Create 5-byte jump from original location to code cave (skip the float, jump to instruction)
            jmp_to_offset = (self.newmem + 4) - (self.no_spread_addr + 5)  # Jump to the movss instruction
            jmp_bytes = bytes([0xE9]) + jmp_to_offset.to_bytes(4, 'little', signed=True) + bytes([0x90])
            
            print(f"Writing hook at {hex(self.no_spread_addr)}: {jmp_bytes.hex()}")
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in jmp_bytes), self.no_spread_addr, 6)
            
            self.enabled = True
            print("No spread enabled!")
            return True
            
        except Exception as e:
            print(f"Error setting up hook: {e}")
            import traceback
            traceback.print_exc()
            if self.newmem:
                utility.freeMemory(self.proc_handle, self.newmem)
            if self.trampoline:
                utility.freeMemory(self.proc_handle, self.trampoline)
            return False
    
    def disable(self):
        """Disable no spread by restoring original bytes"""
        if not self.enabled:
            return
        
        # Restore original bytes
        if self.original_bytes and self.no_spread_addr:
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in self.original_bytes), self.no_spread_addr, len(self.original_bytes))
        
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

