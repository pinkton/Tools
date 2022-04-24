import angr, sys, os

def main(argv):
    project = angr.Project(argv[1]) #Usage - script.py [binary]

    #Start ANGR at Main() with 'entry_state'
    initial_state = project.factory.entry_state(
        add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

    #Binary manager for manipulating
    simulation = project.factory.simgr(initial_state)

    #The hex address for the string output of "Good Job" aka correct password with "find" but also the hex address for an area we categorically don't want to go into with "avoid"
    simulation.explore(find=0x4012AF,avoid=0x401262)

    #Checks whether ANGR has managed to find a solution
    if simulation.found:
        #Stops searching if found a state that works
        solution_state = simulation.found[0]
        
        #Prints out the password that it found to be correct
        print("\nFound this;\n" + solution_state.posix.dumps(sys.stdin.fileno()).decode())
        
    else:
        #ANGR didn't find the password - This example should work, so failure means incorrect information
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)