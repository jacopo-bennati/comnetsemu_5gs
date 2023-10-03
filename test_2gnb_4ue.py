#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import utility
from pyfiglet import Figlet

if __name__ == "__main__":

    # Inizializza l'oggetto Figlet con uno stile di testo specifico (puoi scegliere tra i vari stili disponibili)
    f = Figlet(font='slant')

    # Stampa un messaggio di benvenuto con uno stile artistico
    print(f.renderText('TestNet!'))

    container_names = utility.evnironment_check()
    subscribers_info = utility.get_subscriber_info()
    ue_details = utility.get_ue_details_dictionary(container_names, subscribers_info)
    
    # Loop per gestire i comandi
    while True:
        command = input("testnet> ")

        # Qui puoi gestire i comandi inseriti dall'utente
        # Ad esempio, se l'utente inserisce "latency", esegui il test di latenza, ecc.

        if command == "latency":
            # Esegui il test di latenza
            pass
        elif command == "bandwidth":
            # Esegui il test di banda
            pass
        elif command == "show details":
            # Mostra i dettagli
            pass
        elif command == "exit":
            # Esci dal loop
            break
        else:
            print("Comando sconosciuto. Inserisci un comando valido.")
        