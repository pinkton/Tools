import angr, sys

def main(argv):
    project = angr.Project(argv[1]) #Usage - script.py [binary]

    #Start ANGR at Main() with 'entry_state'
    initial_state = project.factory.entry_state(
        add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

    #Binary manager for manipulating
    simulation = project.factory.simgr(initial_state)

    def looks_good(state):
        #Keeps track of what has been found so far
        stdout_output = state.posix.dumps(sys.stdout.fileno())
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
        
        #Prints out the password that it found to be correct
        print("\nFound this;\n" + solution_state.posix.dumps(sys.stdin.fileno()).decode())
        
    else:
        #ANGR didn't find the password - This example should work, so failure means incorrect information
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)