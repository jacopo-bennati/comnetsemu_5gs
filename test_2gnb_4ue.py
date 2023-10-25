#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import utility
import os
from pyfiglet import Figlet
import readline

# Regexp
REGEXP_UE = r'(ue\d)'
REGEXP_GNB = r'(gnb\d)'

def main():

    # Elenco dei comandi disponibili per il completamento automatico
    available_cmds = ["latency", "bandwidth", "nodes", "show_details", "exit", "clear", "help"]
    latency_params = ["-h" ,"-c", "NAME 1 2 N ... , ..."]
    bandwidth_params = ["-h", "NAME 1 2 N ... , ..."]
    
    # ---------------------------------------------------------------------

    container_names = utility.evnironment_check()

    # Parse list of containers to separate UEs and GNBs
    ue_containers = utility.from_list_to_string_with_regex(REGEXP_UE, container_names)
    user_equipments = utility.get_ue_dictionary(ue_containers)
    base_stations = utility.from_list_to_string_with_regex(REGEXP_GNB, container_names)

    subscription_details = utility.get_subscriptions_dictionary(ue_containers) ## sarebbe da sostituire con user_equipments
    
    # TODO: prendere dal file di log di smf il link tra imsi e ue
    ue_details = utility.check_interfaces(ue_containers)  ## sarebbe da sostituire con user_equipments

    # ---------------------------------------------------------------------
    
    # Funzione per il completamento automatico dei comandi
    def autocomplete(text, state):
        options = [cmd for cmd in available_cmds if cmd.startswith(text)]
        return options[state] if state < len(options) else None

    # Configura la funzione di completamento automatico
    readline.set_completer(autocomplete)
    readline.parse_and_bind("tab: complete")
    
    # Loop per gestire i comandi
    while True:
        command = input("testnet> ")

        # Separa i comandi e gli argomenti
        parts = command.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd == "latency":
            
            skip = False
            concurrency_flag = False
            containers_to_test = {}
            
            # Variabile per tenere traccia dell'attuale container UE
            current_ue = None
            
            for arg in args:
                if arg == '-h' :
                    print(f"\t Available arguments: ", " ,".join(latency_params))
                    print(f"\t Usage: latency [-c] [NAME 1 2 N, NAME 1 2 N ...]")
                    skip = True
                elif arg == '-c':
                    concurrency_flag = True
                elif arg.startswith("-"):
                        print(f"testnet> Error: Unknown argument {arg}")
                        print(f"\t Usage: latency [-c] [NAMES ...]")
                        skip = True
                else:
                    # Se l'argomento è un nome di container, impostalo come container attuale
                    if arg in user_equipments:
                        if current_ue != arg: # Evita di sovrascrivere il precedente se si ripete
                            current_ue = arg
                            containers_to_test[current_ue] = []
                    # Se l'argomento è un numero, verifica se è un indice valido per il container attuale
                    elif current_ue is not None and arg.isdigit():
                        indices = user_equipments.get(current_ue)
                        if int(arg) in indices:
                            containers_to_test[current_ue].append(int(arg))
                        else:
                            print(f"testnet> Error: Invalid index {arg} for container {current_ue}")
                            print(f"\t Valid indicies for {current_ue} are: {indices}")
                            skip = True
                    else:
                        print(f"testnet> Error: Unknown argument {arg}")
                        print(f"\t Valid args are: {list(user_equipments.keys())}")
                        skip = True
            
            if skip:
                continue
            
            if not containers_to_test:
                containers_to_test = user_equipments

            if concurrency_flag:
                print(f"Eseguo il test di latenza in modo concorrente sui container: {containers_to_test}")
                utility.latency_test(containers_to_test, ue_details, True)
            else:
                print(f"Eseguo il test di latenza in modo normale sui container: {containers_to_test}")
                utility.latency_test(containers_to_test, ue_details)
                
        elif cmd == "bandwidth":

            skip = False
            containers_to_test = {}
            
            # Variabile per tenere traccia dell'attuale container UE
            current_ue = None

            for arg in args:
                if arg == '-h' :
                    print(f"\t Available arguments: ", " ,".join(bandwidth_params))
                    print(f"\t Usage: bandwidth [NAME 1 2 N, NAME 1 2 N ...]")
                    skip = True
                elif arg.startswith("-"):
                        print(f"testnet> Error: Unknown argument {arg}")
                        print(f"\t Usage: bandwidth [NAMES ...]")
                        skip = True
                else:
                    # Se l'argomento è un nome di container, impostalo come container attuale
                    if arg in user_equipments:
                        if current_ue != arg: # Evita di sovrascrivere il precedente se si ripete
                            current_ue = arg
                            containers_to_test[current_ue] = []
                    # Se l'argomento è un numero, verifica se è un indice valido per il container attuale
                    elif current_ue is not None and arg.isdigit():
                        indices = user_equipments.get(current_ue)
                        if int(arg) in indices:
                            containers_to_test[current_ue].append(int(arg))
                        else:
                            print(f"testnet> Error: Invalid index {arg} for container {current_ue}")
                            print(f"\t Valid indicies for {current_ue} are: {indices}")
                            skip = True
                    else:
                        print(f"testnet> Error: Unknown argument {arg}")
                        print(f"\t Valid args are: {list(user_equipments.keys())}")
                        skip = True
            
            if skip:
                continue
            
            if not containers_to_test:
                containers_to_test = user_equipments
                
            print(f"Eseguo il test di banda sui container: {containers_to_test}")
            utility.bandwith_test(containers_to_test, ue_details)
        elif cmd == "nodes":

            skip = False
            containers_to_test = {}
            
            # Variabile per tenere traccia dell'attuale container UE
            current_ue = None
            
            for arg in args:
                if arg == '-h' :
                    print(f"\t Available arguments: ", " ,".join(bandwidth_params))
                    print(f"\t Usage: latency [-c] [NAME 1 2 N, NAME 1 2 N ...]")
                    skip = True
                elif arg.startswith("-"):
                        print(f"testnet> Error: Unknown argument {arg}")
                        print(f"\t Usage: latency [-c] [NAMES ...]")
                        skip = True
                else:
                    # Se l'argomento è un nome di container, impostalo come container attuale
                    if arg in user_equipments:
                        if current_ue != arg: # Evita di sovrascrivere il precedente se si ripete
                            current_ue = arg
                            containers_to_test[current_ue] = []
                    # Se l'argomento è un numero, verifica se è un indice valido per il container attuale
                    elif current_ue is not None and arg.isdigit():
                        indices = user_equipments.get(current_ue)
                        if int(arg) in indices:
                            containers_to_test[current_ue].append(int(arg))
                        else:
                            print(f"testnet> Error: Invalid index {arg} for container {current_ue}")
                            print(f"\t Valid indicies for {current_ue} are: {indices}")
                            skip = True
                    else:
                        print(f"testnet> Error: Unknown argument {arg}")
                        print(f"\t Valid args are: {list(user_equipments.keys())}")
                        skip = True
            
            if skip:
                continue
            
            if not containers_to_test:
                containers_to_test = user_equipments
                
            utility.show_nodes(containers_to_test, ue_details)
        elif cmd == "show_details":
            # Mostra i dettagli
            utility.print_sub_detail_table(subscription_details)
        elif cmd == "help":
            # Stampa un elenco di comandi disponibili
            utility.help()
        elif cmd == "clear":
            # Pulisce la shell
            os.system("clear")
            print(f.renderText('TestNet!'))
        elif cmd == "exit":
            # Esci dal loop
            break
        else:
            print("Comando sconosciuto. Inserisci un comando valido.")

if __name__ == "__main__":
    
    f = Figlet(font='slant')
    print(f.renderText('TestNet!'))

    main()