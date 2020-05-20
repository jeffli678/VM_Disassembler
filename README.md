# VM_Disassembler
A recursive disassembler written in Python. Best suitable for VMs in CTFs. 

See example.py for a disassembler for https://crackmes.one/crackme/5bc0fe0033c5d4110a29b296. 

The VM_Diassembler class should be initialized with four parameters:

```Python
vm_dis = VM_Disassembler(vm_code, disassembler, entry_point, look_ahead_len)
```

Where ```vm_code``` is the code to disassemble (a list of integer bytes); ```disassembler``` is the disassembler function (see below); ```entry_point``` is the offset of the first instruction; ```look_ahead_len``` specifies how many bytes to consider when disassembling the current instruction. This can be set to the max length of an instruction. Leave it to 0 if unsure. 

The user only needs to write a disassembler() function which disassembles one instruction. The VM_Disassembler will handler all the other stuff.

```Python
def disassembler(addr, data):
    # hard work here
    return instr_len, instr_text, possible_next_addrs
```

disassembler() takes two parameters:

```addr```: the current address

```data```: the data to disassemble

It should return three things:

```instr_len```: the length of the current instruction

```instr_text```: the disassembly text of the current instruction

```possible_next_addrs```: a list of possible next addresses after the current instruction