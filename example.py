from VM_Disassembler import VM_Disassembler
import struct
from io import open

def bytes_to_word(val_bytes):
    return val_bytes[0] + 0x100 * val_bytes[1]

def bytes_to_int(val_bytes):
	val = 0
	for byte_val in val_bytes[::-1]:
		val *= 0x100
		val += byte_val
	return val

def offset_to_addr(offset):
	vm_start = 0x1190
	return offset - vm_start

regs = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 
		'rdi', 'rsi', 'rbp', 'rbx', 'rdx', 'rax', 'rcx', 'rsp', 'rip', 'eflags']

def disassembler(addr, data):

	instr_len = 0xe
	possible_next_addrs = [addr + instr_len]
	# skip the invalid ud2 instruciton in the beginning
	data = data[2 : ]
	op_code = data[8]

	if op_code == 9:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)
		addr = offset_to_addr(op1)
		op2 = data[9]
		if op2 == 0x10:
			instr_text = 'jmp 0x%x' % (addr)
		else:
			instr_text = '%s = 0x%x' % (regs[op2], op1)
	elif op_code == 0x24:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)
		op2 = data[9]
		op3 = data[0xa]
		instr_text = 'cmp %s, 0x%x' % (regs[op3], op1)
		instr_text += '; setne %s' % (regs[op2])
	elif op_code == 0x2a:
		op1 = data[0xa]
		instr_text = 'cmp %s, 0x0; ifne ret' % (regs[op1])
	elif op_code == 0x2c:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)
		op2 = data[9]
		op3 = data[0xa]
		instr_text = 'add %s, %s, 0x%x' % (regs[op2], regs[op3], op1)
	elif op_code == 0x10:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)
		op2 = data[9]
		op3 = data[0xa]
		instr_text = 'mov %s, *(%s + 0x%x)' % (regs[op2], regs[op3], op1)
	elif op_code == 0x15:
		# op2 = data[9]
		op3 = data[0xa]
		instr_text = 'push %s' % (regs[op3])
	elif op_code == 0x18:
		op2 = data[9]
		op3 = data[0xa]
		instr_text = 'mov %s, %s' % (regs[op2], regs[op3])
	elif op_code == 0x14:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)
		op2 = data[0xa]
		op3 = data[0xb]
		instr_text = '*(%s + 0x%x) = %s' % (regs[op2], op1, regs[op3])
	elif op_code == 0x28:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)		
		addr = offset_to_addr(op1)
		instr_text = 'call 0x%x' % (addr)
	elif op_code == 0x27:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)
		op2 = data[0xa]
		addr = offset_to_addr(op1)
		instr_text = 'cmp %s, 0; jne 0x%x' % (regs[op2], addr)
	elif op_code == 0xa:
		op1_data = data[0 : 8]
		op1 = bytes_to_int(op1_data)
		op2 = data[0xa]
		op3 = data[0x9]
		instr_text = 'mov %s, byte* (%s + 0x%x)' % (regs[op3], regs[op2], op1)
	elif op_code == 0x1:
		op1 = data[0xa]
		op2 = data[0xb]
		op3 = data[0x9]
		instr_text = 'add %s, %s, %s' % (regs[op3], regs[op2], regs[op1])
	elif op_code == 0x8:
		op1 = data[0xa]
		op2 = data[0x9]
		instr_text = '%s = neg %s' % (regs[op2], regs[op1])
	elif op_code == 0x17:
		op1 = data[0x9]
		instr_text = 'pop %s' % (regs[op1])
	elif op_code == 0x26:
		op1 = data[0xa]
		op2_data = data[0 : 8]
		op2 = bytes_to_int(op2_data)
		addr = offset_to_addr(op2)
		instr_text = 'cmp %s, 0x0; je 0x%x modified' % (regs[op1], addr)
	elif op_code == 0x29:
		instr_text = 'ret'
	elif op_code == 0x2b:
		op1 = data[0xa]
		instr_text = 'cmp %s, 0x0; if equal ret' % (regs[op1])
	elif op_code == 0x2e:
		op1 = data[0xa]
		op3 = data[0x9]
		op2_data = data[0 : 8]
		op2 = bytes_to_int(op2_data)
		instr_text = 'shl %s, %s, 0x%x' % (regs[op3], regs[op1], op2)
	elif op_code == 2:
		op1 = data[0xa]
		op2 = data[0xb]
		op3 = data[0x9]
		instr_text = 'sub %s, %s, %s' % (regs[op3], regs[op1], regs[op2])
	elif op_code == 3:
		op1 = data[0xa]
		op2 = data[0xb]
		op3 = data[0x9]
		instr_text = 'imul %s, %s, %s' % (regs[op3], regs[op2], regs[op1])
	elif op_code == 0x1b:
		op1 = data[0xa]
		op2 = data[0xb]
		op3 = data[0x9]
		instr_text = 'xor %s, %s, %s' % (regs[op3], regs[op1], regs[op2])
	elif op_code == 0x19:
		op1 = data[0xa]
		op2 = data[0xb]
		op3 = data[0x9]
		instr_text = 'or %s, %s, %s' % (regs[op3], regs[op1], regs[op2])
	elif op_code == 0x21:
		op1 = data[0xa]
		op2 = data[0xb]
		op3 = data[0x9]
		instr_text = 'cmp %s, %s; sete %s' % (regs[op2], regs[op1], regs[op3])
	else:
		instr_text = 'opcode used: 0x%x' % op_code

	return instr_len, instr_text, possible_next_addrs

def main():
    vm_code = open('mem.txt', 'rb').read()
    vm_code = list(vm_code)
    try:
        # python 2-3 compatability
        vm_code = [ord(c) for c in vm_code]
    except:
        pass
    
    # we need to write a disassembler(addr, data) that disassembles the data at addr, and return a list of: 1). the length of the current instruction; 2). the disassembly text of the current instruction; 3). the list of possible next addresses
    # if the current instruction is not a branch, then probably the possible next address is jus the address after this instruction; if it is a branch, then we might have two possible next addresses
    vm_dis = VM_Disassembler(vm_code, disassembler, 0, 0xe)
    vm_dis.disassemble()

if __name__ == '__main__':
    main()