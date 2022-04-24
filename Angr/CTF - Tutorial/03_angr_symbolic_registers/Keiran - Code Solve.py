    #This challenge has multiple passwords to enter, with ANGR not understanding
    #scanf, so we have to tell it how to work by injecting inputs into  the required registers
    
import angr, sys, claripy

def main(argv):
    project = angr.Project(argv[1]) #Usage - script.py [binary]

    #Start ANGR at defined location, therefore requiring "blank_state"
    #with the desired start in hex. This example, should go back to Main()
    #after the scanf function has completed. Don't try do it straight
    #after the scanf itself, as it breaks ANGR (clearly can't move data if it doens't exist!)
    start = 0x4014E0
    initial_state = project.factory.blank_state(
        addr = start,
        add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

        #mov     [rbp+var_C], eax     These are part of the asm after "get user input"
        #mov     [rbp+var_8], ebx --  which means they are the registers we need
        #mov     [rbp+var_4], edx     to inject data into, to help ANGR work its magic!
        
    #Since we're dealing with a 32bit program, we know the size CAN'T be 64 bits
    #We therefore must look at the "complex_fucntion" to understand what's happening
    #We see maniuplation against the EAX register in each function, meaning it's 32 bits
    #We must also tell it what should go where.
    
    password0_bits = 32 
    password0 = claripy.BVS('password0', password0_bits)
    initial_state.regs.eax = password0

    password1_bits = 32
    password1 = claripy.BVS('password1', password1_bits)
    initial_state.regs.ebx = password1

    password2_bits = 32
    password2 = claripy.BVS('password2', password2_bits)
    initial_state.regs.edx = password2

    #Binary manager for manipulating
    simulation = project.factory.simgr(initial_state)

    def looks_good(state):
        #Keeps track of what has been found so far
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        print(stdout_output)
        #Has the string "Good Job" been found? if so, print password
        return 'Good Job.'.encode() in stdout_output
    
    def stop_hunting(state):
        #Keeps track of what has been found so far, with the string "Try Again" 
        #meaning to stop searching down this path
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return 'Try again.'.encode() in stdout_output  
        
    #Find is linked to the function "looks_good" and allows ANGR to keep searching
    #if it believes it hasn't failed/finished, whereas the "stop_hunting" function
    #will prevent it wasting more cycles on code we know to be a failure.
    simulation.explore(find=looks_good,avoid=stop_hunting)

    #Checks whether ANGR has managed to find a solution
    if simulation.found:
        #Stops searching if found a state that works
        solution_state = simulation.found[0]
        
        #Prints out the password that it found to be correct, but format it first
        solution0 = solution_state.solver.eval(password0)
        solution1 = solution_state.solver.eval(password1)
        solution2 = solution_state.solver.eval(password2)
        solution = ' '.join(map('{:x}'.format, [ solution0, solution1, solution2 ]))
        print("\nFound this;\n" + solution)
        
    else:
        #ANGR didn't find the password - This example should work, so failure means incorrect information
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)