#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import utility
import os
from pyfiglet import Figlet
import readline
import pprint
from python_modules.Open5GS import Open5GS

# Regular Expressions
REGEXP_UE = r'(ue\d)'
REGEXP_GNB = r'(gnb\d)'

def main():
    """
    Main function to handle user commands and execute corresponding tests.
    """
    
    # List of available commands for autocomplete
    available_cmds = ["latency", "bandwidth", "nodes", "show_details", "exit", "clear", "help"]
    
    # Command-line parameters for latency and bandwidth commands
    latency_params = ["-h", "-c", "NAME 1 2 N, ..."]
    bandwidth_params = ["-h", "NAME 1 2 N, ..."]
    
    # ---------------------------------------------------------------------
    
    # Check the environment and get a list of container names
    container_names = utility.environment_check()
    
    # Separate UEs and GNBs from the list of container names
    ue_containers = utility.from_list_to_string_with_regex(REGEXP_UE, container_names)
    user_equipments = utility.get_ue_dictionary(ue_containers)
    user_equipments_list = utility.get_ue_list(user_equipments)
    
    # Check interfaces for each UE and get details
    ue_details = utility.check_interfaces(user_equipments)
    
    # Get subscription details
    subscription_details = utility.get_subscriptions_dictionary(ue_details)
    
    # ---------------------------------------------------------------------
    
    # Function for command auto-completion
    def autocomplete(text, state):
        options = [cmd for cmd in available_cmds if cmd.startswith(text)]
        return options[state] if state < len(options) else None

    # Configure auto-completion function
    readline.set_completer(autocomplete)
    readline.parse_and_bind("tab: complete")
    
    # Loop to handle user commands
    while True:
        command = input("TestNet5G> ")

        # Separate commands and arguments
        parts = command.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd == "latency":
            # Latency test command
            skip = False
            concurrency_flag = False
            containers_to_test = {}
            current_ue = None  # Variable to track the current UE container
            
            for arg in args:
                if arg == '-h':
                    print(f"\t Available arguments: ", ", ".join(latency_params))
                    print(f"\t Usage: latency [-c] [NAME 1 2 N, NAME 1 2 N ...]")
                    skip = True
                    break
                elif arg == '-c':
                    concurrency_flag = True
                elif arg.startswith("-"):
                    print(f"TestNet5G> Error: Unknown argument {arg}")
                    print(f"\t Usage: latency [-c] [NAMES ...]")
                    skip = True
                    break
                else:
                    if arg in user_equipments_list:
                        if current_ue != arg:
                            current_ue = arg
                            containers_to_test[current_ue] = []
                    elif current_ue is not None and arg.isdigit():
                        indices = user_equipments_list.get(current_ue)
                        if int(arg) in indices:
                            containers_to_test[current_ue].append(int(arg))
                        else:
                            print(f"TestNet5G> Error: Invalid index {arg} for container {current_ue}")
                            print(f"\t Valid indices for {current_ue} are: {indices}")
                            skip = True
                            break
                    else:
                        print(f"TestNet5G> Error: Unknown argument {arg}")
                        print(f"\t Valid args are: {list(user_equipments_list.keys())}")
                        skip = True
                        break
            
            if skip:
                continue
            
            if not containers_to_test:
                containers_to_test = user_equipments_list

            if concurrency_flag:
                print(f"Running latency test concurrently on containers: {containers_to_test}")
                utility.latency_test(containers_to_test, ue_details, True)
            else:
                print(f"Running latency test normally on containers: {containers_to_test}")
                utility.latency_test(containers_to_test, ue_details)
                
        elif cmd == "bandwidth":
            # Bandwidth test command
            skip = False
            containers_to_test = {}
            current_ue = None  # Variable to track the current UE container
            
            for arg in args:
                if arg == '-h':
                    print(f"\t Available arguments: ", ", ".join(bandwidth_params))
                    print(f"\t Usage: bandwidth [NAME 1 2 N, NAME 1 2 N ...]")
                    skip = True
                    break
                elif arg.startswith("-"):
                    print(f"TestNet5G> Error: Unknown argument {arg}")
                    print(f"\t Usage: bandwidth [NAMES ...]")
                    skip = True
                    break
                else:
                    if arg in user_equipments_list:
                        if current_ue != arg:
                            current_ue = arg
                            containers_to_test[current_ue] = []
                    elif current_ue is not None and arg.isdigit():
                        indices = user_equipments_list.get(current_ue)
                        if int(arg) in indices:
                            containers_to_test[current_ue].append(int(arg))
                        else:
                            print(f"TestNet5G> Error: Invalid index {arg} for container {current_ue}")
                            print(f"\t Valid indices for {current_ue} are: {indices}")
                            skip = True
                            break
                    else:
                        print(f"TestNet5G> Error: Unknown argument {arg}")
                        print(f"\t Valid args are: {list(user_equipments_list.keys())}")
                        skip = True
                        break
            
            if skip:
                continue
            
            if not containers_to_test:
                containers_to_test = user_equipments_list
                
            print(f"Running bandwidth test on containers: {containers_to_test}")
            utility.bandwidth_test(containers_to_test, ue_details)
            
        elif cmd == "nodes":
            # Show nodes command
            skip = False
            containers_to_test = {}
            current_ue = None  # Variable to track the current UE container
            
            for arg in args:
                if arg == '-h':
                    print(f"\t Available arguments: ", ", ".join(bandwidth_params))
                    print(f"\t Usage: latency [-c] [NAME 1 2 N, NAME 1 2 N ...]")
                    skip = True
                elif arg.startswith("-"):
                    print(f"TestNet5G> Error: Unknown argument {arg}")
                    print(f"\t Usage: latency [-c] [NAMES ...]")
                    skip = True
                else:
                    if arg in user_equipments_list:
                        if current_ue != arg:
                            current_ue = arg
                            containers_to_test[current_ue] = []
                    elif current_ue is not None and arg.isdigit():
                        indices = user_equipments_list.get(current_ue)
                        if int(arg) in indices:
                            containers_to_test[current_ue].append(int(arg))
                        else:
                            print(f"TestNet5G> Error: Invalid index {arg} for container {current_ue}")
                            print(f"\t Valid indices for {current_ue} are: {indices}")
                            skip = True
                    else:
                        print(f"TestNet5G> Error: Unknown argument {arg}")
                        print(f"\t Valid args are: {list(user_equipments_list.keys())}")
                        skip = True
            
            if skip:
                continue
            
            if not containers_to_test:
                containers_to_test = user_equipments_list
                
            utility.show_nodes(containers_to_test, ue_details)
            
        elif cmd == "show_details":
            # Show subscription details command
            utility.print_sub_detail_table(subscription_details)
            
        elif cmd == "help":
            # Print a list of available commands
            utility.help()
            
        elif cmd == "clear":
            # Clear the shell
            os.system("clear")
            print(f.renderText('TestNet5G'))
            
        elif cmd == "exit":
            # Exit the loop
            break
        else:
            print("Unknown command. Enter a valid command.")

if __name__ == "__main__":
    # Display the TestNet5G banner
    f = Figlet(font='slant')
    print(f.renderText('TestNet5g'))

    # Run the main function
    main()
