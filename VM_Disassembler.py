class VM_Disassembler:
    
    def __init__(self, code, disassembler, entry_point, look_ahead_len = 0):
        # code is a list of ints 
        self.code = code
        # this the core disassembler function
        # the user needs to write it
        self.disassembler = disassembler
        self.entry_point = entry_point

		# how many bytes to check when disassembling the current instruction
		# this can be set to the max length of an instruction
		# leave it to 0 if unsure
        self.look_ahead_len = look_ahead_len
        
        # the set of addresses that we have already processed
        self.disassembled_addr = set()
        # the list of addresses to process
        self.disassemble_queue = [self.entry_point]

	# utility 
    def format_bytes(self, data):
        s = ''
        for c in data:
            s += '%02x' % c
        return s

	# the core function for the recursive disassembly
    def disassemble(self):
		# check whethe we have adress to disassemble
        while len(self.disassemble_queue) > 0:

            addr = self.disassemble_queue.pop()
            if addr in self.disassembled_addr:
                continue
            else:
                self.disassembled_addr.add(addr)

            if addr >= len(self.code):
				# there is probably an error in the disassembler
				# but for now we just ignore it
                continue
            
			# prepare the data and send it to self.disassembler()
            if self.look_ahead_len == 0:
                data_to_parse = self.code[addr : ]
            else:
                data_to_parse = self.code[addr : addr + self.look_ahead_len]
            instr_len, instr_text, possible_next_instrs = \
                self.disassembler(addr, data_to_parse)
            
			# put every next possible addresses into the queue
            for next_addr in possible_next_instrs:
                self.disassemble_queue.append(next_addr)

			# print the address, raw bytes, and the disassembly text of the current instruction
            instr_bytes = self.code[addr : addr + instr_len]
            print('0x%x %s %s' % (addr, self.format_bytes(instr_bytes), instr_text))
        
        print('Pasring done! Good luck with reversing')
