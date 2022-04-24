import os
os.add_dll_directory("C:/Program Files/Python39/DLLs")
from triton import TritonContext,Instruction,ARCH

# Create the Triton context with a defined architecture
ctx = TritonContext(ARCH.X86_64)

# Define concrete values (optional)
ctx.setConcreteRegisterValue(ctx.registers.rip, 0x40000)

# Symbolize data (optional)
ctx.symbolizeRegister(ctx.registers.rax, 'my_rax')

# Execute instructions
ctx.processing(Instruction(b"\x48\x35\x34\x12\x00\x00")) # xor rax, 0x1234
ctx.processing(Instruction(b"\x48\x89\xc1")) # mov rcx, rax

# Get the symbolic expression
rcx_expr = ctx.getSymbolicRegister(ctx.registers.rcx)
print(rcx_expr)

# Solve constraint
ctx.getModel(rcx_expr.getAst() == 0xdead)

# 0xcc99 XOR 0x1234 is indeed equal to 0xdead
hex(0xcc99 ^ 0x1234)
