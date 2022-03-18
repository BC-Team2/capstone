# Create command line argument structure
# (positional?) individual target, switch for csv, switch for remediate
import pssh_session

query_prog = 'vim'



def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi("I'm a program")  # Stuff goes to run the script
    version = pssh_session.query_targets(query_prog)  # Get hostname/version for a computer
    print(version)
