#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import utility
import os
from pyfiglet import Figlet
import readline

# Regexp
REGEXP_UE = r'(ue_\d)'
REGEXP_GNB = r'(gnb_\d)'

def main():

    # Elenco dei comandi disponibili per il completamento automatico
    available_cmds = ["latency", "bandwidth", "show_details", "exit", "clear", "help"]
    latency_params = ["-c/--concurrent", "-n/--names", "-h/--help"]
    
    # ---------------------------------------------------------------------

    container_names = utility.evnironment_check()

    user_equipments = utility.from_list_to_string_with_regex(REGEXP_UE, container_names)
    base_stations = utility.from_list_to_string_with_regex(REGEXP_GNB, container_names)

    subscribers_info = utility.get_subscriber_info()
    ue_details = utility.get_ue_details_dictionary(user_equipments, subscribers_info)

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
        
            concurrency_flag = False
            names_flag = False
            containers_to_test = []
            error = False
            # To pop from start
            if args:
                args.reverse()

            while args:
                arg = args.pop()
                if arg == "-h" or arg == "--help":
                    print(f"\t Available arguments,", " ".join(latency_params))
                    print(f"\t Usage: latency [-c] [-n NAMES [NAMES ...]]")
                    error = True
                    break
                elif arg == "-c" or arg == "--concurrent":
                    concurrency_flag = True
                elif arg == "-n" or arg == "--names":
                    names_flag = True
                    containers_to_test = []
                elif arg.startswith("-"):
                    print(f"testnet> Error: Unknown argument {arg}")
                    print(f"\t Usage: latency [-c] [-n NAMES [NAMES ...]]")
                    error = True
                    break
                else:
                    if names_flag:
                        containers_to_test.append(arg)
                    else:
                        print(f"testnet> Error: Unknown argument {arg}")
                        print(f"\t Usage: latency [-c] [-n NAMES [NAMES ...]]")
                        error = True
                        break

            if error:
                continue

            if names_flag and len(containers_to_test) < 2:
                print(f"testnet> Error: argument -n/--names: expected at least two arguments")
                print(f"\t Usage: latency [-c] [-n NAMES [NAMES ...]]")
                continue
            elif not concurrency_flag and not names_flag:
                print("Esegui il test di latenza in modo normale su tutti i container")
                utility.latency_test(user_equipments)
            elif concurrency_flag and not names_flag:
                print("Esegui il test di latenza in modo concorrente su tutti i container")
                utility.latency_test(user_equipments, True)
            elif concurrency_flag and names_flag:
                print(f"Esegui il test di latenza in modo concorrente sui container specificati: {containers_to_test}")
                utility.latency_test(containers_to_test, True)
            elif names_flag:
                print(f"Esegui il test di latenza in modo normale sui container specificati: {containers_to_test}")
                utility.latency_test(containers_to_test)
            else:
                print(f"testnet> Error: argument -n/--names: expected at least two arguments")
                print(f"\t Usage: latency [-c] [-n NAMES [NAMES ...]]")
                continue

        elif cmd == "bandwidth":
            # Esegui il test di banda
            pass
        elif cmd == "show_details":
            # Mostra i dettagli
            utility.print_sub_detail_table(ue_details)
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