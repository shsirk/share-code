from winappdbg import Debug, EventHandler, HexDump, CrashDump, win32
from capstone import *
from capstone.x86 import *
from xprint import to_hex, to_x, to_x_32
        
start = 0
end   = 0
block_instructions =  {}
#=============================== regs mapping ============================================
general_regs_mapping = { 
        ("al", "ah", "ax", "eax", "rax") : "Rax", 
        ("bl", "bh", "bx", "ebx", "rbx") : "Rbx",
        ("cl", "ch", "cx", "ecx", "rcx") : "Rcx",
        ("dl", "dh", "dx", "edx", "rdx") : "Rdx",
        ("spl", "sp", "esp", "rsp")             : "Rsp",
        ("bpl", "bp", "ebp", "rbp")             : "Rbp",
        ("sil", "si", "esi", "rsi")             : "Rsi",
        ("dil", "di", "edi", "rdi")             : "Rdi",
        
        ("r8", "r8d", "r8w", "r8b")      : "R8" , 
        ("r9", "r9d", "r9w", "r9b")      : "R9" , 
        ("r10", "r10d", "r10w", "r10b")      : "R10" , 
        ("r11", "r11d", "r11w", "r11b")      : "R11" , 
        ("r12", "r12d", "r12w", "r12b")      : "R12" , 
        ("r13", "r13d", "r13w", "r13b")      : "R13" , 
        ("r14", "r14d", "r14w", "r14b")      : "R14" , 
        ("r15", "r15d", "r15w", "r15b")      : "R15" , 
        ("ip", "eip", "rip" )            : "Rip",
        
        ("xmm0",)   : "Xmm0",
        ("xmm1",)   : "Xmm1",
        ("xmm2",)   : "Xmm2",
        ("xmm3",)   : "Xmm3",
        ("xmm4",)   : "Xmm4",
        ("xmm5",)   : "Xmm5",
        ("xmm6",)   : "Xmm6",
        ("xmm7",)   : "Xmm7",
        ("xmm8",)   : "Xmm8",
        ("xmm9",)   : "Xmm9",
        ("xmm10",)   : "Xmm10",
        ("xmm11",)   : "Xmm11",
        ("xmm12",)   : "Xmm12",
        ("xmm13",)   : "Xmm13",
        ("xmm14",)   : "Xmm14",
        ("xmm15",)   : "Xmm15",
}

x86_gp_registers = {}
for k, v in general_regs_mapping.items():
    for key in k:
        x86_gp_registers[key] = v
#=============================== regs mapping ============================================
        
def hexdump(src, address, length=16, sep='.'):
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
	lines = []
	for c in xrange(0, len(src), length):
		chars = src[c:c+length]
		hex = ' '.join(["%02x" % ord(x) for x in chars])
		if len(hex) > 24:
			hex = "%s %s" % (hex[:24], hex[24:])
		printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
		lines.append("  %08x:  %-*s  |%s|\n" % (address+c, length*3, hex, printable))
	return ''.join(lines)
  
def print_context_information(thread, insn):
    context = thread.get_context()
 
    if insn.mnemonic[0] == "j" or insn.mnemonic == "call":
        print "> %-16x %-04x %-08s %-20s" % ( insn.address, (insn.address - start), insn.mnemonic, insn.op_str)
        return
    
    referenced_regs = [] 
    referenced_mems = []
    
    if len(insn.operands) > 0:
        for i in insn.operands:
            if i.type == X86_OP_REG:
                reg = insn.reg_name(i.reg).encode("utf8")
                referenced_regs.append (reg)

            if i.type == X86_OP_MEM:
                try:
                    operands = insn.op_str.split(",")
                    if "[" in operands[0] : operand_string = operands[0]
                    else: operand_string = operands[1]
                    operand_string = operand_string[operand_string.find("[") : operand_string.find("]") +1] #get the expression [ ]
                    
                    if i.mem.segment != 0:
                        segment_reg = insn.reg_name(i.mem.segment).encode("utf8")
                        operand_string = operand_string.replace(segment_reg, "")
                        
                    if i.mem.base != 0:
                        base_reg = insn.reg_name(i.mem.base).encode("utf8")
                        referenced_regs.append (base_reg)
                        base_reg_value = context[x86_gp_registers[base_reg]]
                        operand_string = operand_string.replace(base_reg, "0x%08x" % base_reg_value)
                    
                    if i.mem.index != 0:
                        index_reg = insn.reg_name(i.mem.index).encode("utf8")
                        referenced_regs.append (index_reg)
                        index_reg_value = context[x86_gp_registers[index_reg]]
                        operand_string = operand_string.replace(index_reg, "0x%08x" % index_reg_value)
                    
                    if i.mem.scale != 1:
                        scale = i.mem.scale
                    
                    if i.mem.disp != 0:
                        disp = to_x(i.mem.disp)
                    
                    referenced_mems.append (operand_string)
                   
                except:
                    print "ERROR: for mem ref"
        
        #print "> %-16x %-04x %-08s %-40s %s" % ( insn.address, (insn.address - start), insn.mnemonic, insn.op_str, \
        #            ", ".join(["%5s: %12x" % (reg, context[x86_gp_registers[reg]]) for reg in referenced_regs]) 
        #        )    
        
        #print "REGS > %s" % ", ".join(["%s: %08x" % (reg, context[x86_gp_registers[reg]]) for reg in referenced_regs]) 
        #for reg in referenced_regs:
        #    print "%20s: %08x" % (reg, context[x86_gp_registers[reg]])
        hex_dump = ""
        if referenced_mems:
            for mem_ref in referenced_mems:
                value = eval (mem_ref)
                try:
                    process = thread.get_process()
                    bytes = process.read (value[0], 16)
                    hex_dump = hexdump(bytes, value[0])
                except WindowsError:
                    pass
        
        print "> %-16x %-04x %-08s %-40s %s  %s" % ( insn.address, (insn.address - start), insn.mnemonic, insn.op_str, \
                    ", ".join(["%5s: %12x" % (reg, context[x86_gp_registers[reg]]) for reg in referenced_regs]) ,
                    hex_dump.strip()
                )
                
def disassemble_block_details(thread, block_start, block_end):
    code = thread.read_code_bytes(block_end - block_start)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, block_start):
        block_instructions[insn.address] = insn
        
def disassemble_block(thread, block_start, block_end):
    code = ""
    try:
        code = thread.read_code_bytes(block_end - block_start)
    except WindowError:
        print "disassemble_block read error!"
        code = "\x90"
        
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, block_start):
        block_instructions[address] = instruction(address, size, mnemonic, op_str)
        
def start_tracing(event):
    print "[*] trace start breakpoint hit!"
    thread = event.get_thread()
    disassemble_block_details(thread, start, end)
    print_context_information( thread, block_instructions[thread.get_pc()])
    
    event.debug.start_tracing( event.get_tid() )
        
def stop_tracing (event):
    print "[*] trace end breakpoint hit!"
    event.debug.stop_tracing( event.get_tid() )

class MyEventHandler( EventHandler ):
    def load_dll(self, event):
        module = event.get_module()
        if module.match_name("wwlib.dll"):
            pid = event.get_pid()
            
            global start, end
            
            start = module.get_base() + 0x0149103c #0x38732c
            end   = module.get_base() + 0x0149143f  #0x387ab9 
            
            print "Setting tracepoints at %08x to %08x" % (start, end)
            
            event.debug.break_at( pid, start, start_tracing )
            event.debug.break_at( pid, end , stop_tracing )
            
    def single_step( self, event ):
        thread = event.get_thread()
        pc     = thread.get_pc()

        global start, end
        if pc >= start and pc <= end:
            global block_instructions
            if pc not in block_instructions:
                print "!!Error > PC %08x not in tracing instructions!" % pc
                return
            print_context_information( thread, block_instructions[pc])
            
    def exception (self, event):
        if event.get_exception_code() == 0xc0000409:
            print "stack overrun detected!"
            event.debug.kill(event.get_pid())
        
def trace_debugger( argv ):
    with Debug( MyEventHandler(), bKillOnExit = True ) as debug:
        debug.execv( argv )
        debug.loop()

if __name__ == "__main__":
    import sys
    trace_debugger( sys.argv[1:] )