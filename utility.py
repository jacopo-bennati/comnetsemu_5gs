import subprocess
import re
import time
import sys
import json
import os
from tabulate import tabulate 
import threading

# Massima quantità di tentativi
MAX_RETRY = 3
# Destinazione test connettività
CONN_DEST = "www.google.com"

# Stampa un elenco di comandi disponibili
def help():
    print("\tComandi disponibili:")
    print("\t\tlatency - Esegui il test di latenza")
    print("\t\tbandwidth - Esegui il test di banda")
    print("\t\tshow details - Mostra i dettagli")
    print("\t\texit - Esci dal programma")
    print("\t\tclear - Pulisci la shell")

def from_list_to_string_with_regex(regexp, list):

    string = ""

    # Check if active containers were found
    if list:
        # Join container names into a single string separated by commas
        string = " ".join(list)
    else:
        print("Empty list.")
    
    return re.findall(regexp, string)

def containers_check():

    print(f"*** Checking containers")

    # Execute the 'docker ps' command and capture the output
    try:
        output = subprocess.check_output(["docker", "ps"]).decode("utf-8")
    except subprocess.CalledProcessError:
        print("Error executing 'docker ps'. Make sure Docker is running.")
        exit(1)

    # Find container names similar to 'ue_n'
    user_equipments = re.findall(r'(\bue_\d+\b)', output)
    base_stations = re.findall(r'(\bgnb_\d+\b)', output)
    container_names = user_equipments + base_stations

    # Sort the list in ascending order
    container_names.sort()

    return container_names

def evnironment_check():
     
    container_names = containers_check()

    # Check if active containers were found
    if container_names:
        # Join container names into a single string separated by commas
        container_names_str = " ".join(container_names)
        print(f"Containers found: {container_names_str}")
    else:
        print("No active containers found, make sure you have started a network topology.")
        exit(1)
    
    return container_names

def check_connectivity(container_name, interface_name, destination):
    try:
        # Esegui il ping all'interno del container senza stampare l'output
        command = f"docker exec {container_name} ping -c 3 -n -I {interface_name} {destination}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Controlla il codice di ritorno del comando
        if result.returncode == 0:
            return True  # Il ping ha avuto successo
        else:
            return False  # Il ping non ha avuto successo
    except Exception as e:
        raise e

def get_upfs_ip():
    command = "docker exec upf_mec ifconfig ogstun | awk '/inet / {print $2}' | tr -d '\n'"
    upf_mec_ip = subprocess.check_output(command, shell=True, universal_newlines=True)
    command = "docker exec upf_cld ifconfig ogstun | awk '/inet / {print $2}'| tr -d '\n'"
    upf_cld_ip = subprocess.check_output(command, shell=True, universal_newlines=True)
    upfs_ip = {
        "upf_cld": upf_cld_ip,
        "upf_mec": upf_mec_ip
    }
    return upfs_ip

def check_interfaces(user_equipments):
    
    upfs_ip = get_upfs_ip()
    
    print(upfs_ip)

    print(f"*** Checking interfaces")

    ue_interfaces_dictionary = {}

    for ue in user_equipments:
        for retry in range(MAX_RETRY + 1):
            try:
                # Run the 'ifconfig' command inside the container
                command = f"docker exec {ue} ifconfig"
                ifconfig_output = subprocess.check_output(command, shell=True, universal_newlines=True)

                # Cerca le interfacce 'uesimtunN' nel testo di output
                interface_pattern = re.compile(r'uesimtun\d+')
                found_interfaces = interface_pattern.findall(ifconfig_output)
                
                interfaces_and_ips = {}

                print(f"{ue} interfaces state:")
                if found_interfaces:
                    for interface in found_interfaces:
                        interfaces_and_ips[interface] = "0.0.0.0"
                        print(f"\t[\u2713] {interface}: active ")
                    ue_interfaces_dictionary[ue] = interfaces_and_ips
                    break  # Interfaces are active, no need to retry
                else:
                    print(f"[\u2717] No active interfaces found")

                # If it's the last retry, exit with an error message
                if retry == MAX_RETRY:
                    raise Exception("Interfaces error: Timeout")

                # If not the last retry, wait for 5 seconds before retrying
                print(f"[\u2717] {ue}: inactive, retrying in 15 seconds...")
                time.sleep(15)

            except Exception as e:
                print(f"An error occurred for container {ue}: {str(e)}")
                print(f"Note that if you just started the topology it might take at least 30s to setup correctly the interfaces (or more depending on network complexity)")
                print(f"If the error persist try running the clean script: ./clean2_2.sh")
                sys.exit(1)

    # Check connectivity
    
    print("*** Testing connectivity")

    for ue in ue_interfaces_dictionary:
        try:
            for interface in ue_interfaces_dictionary[ue]:
                if check_connectivity(ue, interface, CONN_DEST):
                    print(f"\t[\u2713] {ue} using '{interface}': Connessione riuscita")
                else:
                    print(f"\t[\u2717] {ue} using '{interface}': Connessione non riuscita")
                
        except Exception as e:
                print(f"An error occurred for container {ue}: {str(e)}")
                print(f"{ue}: Cannot enstablish connection")
                sys.exit(1)

    return ue_interfaces_dictionary

def get_interfaces_ip():
    # TODO: implement
    return

def get_subscriber_info():
    # Get the path of the current Python script file
    script_path = os.path.abspath(__file__)

    # Get the path of the parent directory of the script file
    prj_folder = os.path.dirname(script_path)

    print("*** Retrieving subscriber information")

    # Load test data from a JSON file
    with open( prj_folder + '/python_modules/subscriber_profile2_2.json', 'r') as json_file:
        subscribers_info = json.load(json_file)
    
    return subscribers_info

def get_ue_details_dictionary(container_names, subscribers_info):

    print("*** Creating a dictionary with UE subscription details")

    # Create a dictionary to associate IMSIs with slice details
    ue_details = {}

    # Iterate through UE container names
    for container_name in container_names:
        for retry in range(MAX_RETRY):
            try:
                # Execute 'docker exec' to enter the container
                command = f"docker exec {container_name} ./nr-cli --dump | cut -d'-' -f2"
                imsi_output = subprocess.check_output(command, shell=True, universal_newlines=True)
                imsi = imsi_output.strip()  # Extract IMSI from the output string

                # Search for IMSI in the JSON file and store slice details
                for subscriber in subscribers_info['subscribers']:
                    if subscriber['imsi'] == imsi:
                        slice_details = []
                        for slice in subscriber['slice']:
                            sst = slice['sst']
                            name = slice['session'][0]['name']
                            uplink = slice['session'][0]['ambr']['uplink']['value']
                            downlink = slice['session'][0]['ambr']['downlink']['value']
                            slice_details.append({
                                'sst': sst,
                                'name': name,
                                'uplink': uplink,
                                'downlink': downlink
                            })
                        
                        ue_details[container_name] = {
                            'imsi': imsi,
                            'slice_details': slice_details
                        }
                
                # Check if imsi is present in the output
                if imsi:
                    print(f"\t[\u2713] {container_name}: active and operating")
                    break  # Imsi obtained, no need to retry

                # If it's the last retry, exit with an error message
                if retry == MAX_RETRY:
                    print(f"[\u2717] Unable to obtain IMSI from {container_name}")
                    print(f"Note that if you just started the topology it might take at least 30s to setup correctly the User equipments (or more depending on network complexity)  ")
                    exit(1)

                # If not the last retry, wait for 5 seconds before retrying
                print(f"[\u2717] Unable to obtain IMSI from {container_name}, retrying in 15 seconds...")
                time.sleep(15)
                
            except Exception as e:
                print(f"An error occurred for container {container_name}: {str(e)}")
    
    return ue_details

def print_sub_detail_table(ue_details):
    # Building the table using tabulate

    print("*** Printing Slice/Service Type details per subscriber ")

    # Define table headers
    headers = ["Name", "IMSI", "SST 1", "Downlink/Uplink 1", "SST 2", "Downlink/Uplink 2"]

    # Create a list for table data
    table_data = []

    # Create a dictionary to keep track of rows for each user/IMSI
    user_rows = {}

    for container_name, details in ue_details.items():
        imsi = details["imsi"]
        if imsi not in user_rows:
            user_rows[imsi] = {
                "Name": container_name,
                "IMSI": imsi,
                "SST 1": "",
                "Downlink/Uplink 1": "",
                "SST 2": "",
                "Downlink/Uplink 2": ""
            }

        for i, slice in enumerate(details["slice_details"]):
            sst_name = slice["name"]
            downlink_uplink = f'{slice["downlink"]} Mbps/ {slice["uplink"]} Mbps'
            user_rows[imsi][f"SST {i + 1}"] = sst_name
            user_rows[imsi][f"Downlink/Uplink {i + 1}"] = downlink_uplink

    # Add user rows to the table data list
    for user_row in user_rows.values():
        table_data.append([user_row[column] for column in headers])

    # Print the table
    table = tabulate(table_data, headers, tablefmt="grid")
    print(table)

# Define a function to run a ping command and capture the output
def run_ping(container_name, interface_name, destination):
    try:
        # print(f"Running ping in {container_name} using interface {interface_name}")
        
        # Run the ping command inside the container
        command = f"docker exec {container_name} ping -c 3 -n -I {interface_name} {destination}"
        ping_output = subprocess.check_output(command, shell=True, universal_newlines=True)
        
        # Use a regular expression to find the ping statistics section
        pattern = re.compile(r'--- www\.google\.com ping statistics ---\n(.*?)$\n', re.DOTALL)
        match = pattern.search(ping_output)
        
        if match:
            ping_statistics = match.group(1)  # Get the ping statistics part
            return ping_statistics
        else:
            return f"Unable to find ping statistics for container {container_name} and interface {interface_name}"
    except Exception as e:
        return f"An error occurred for container {container_name} and interface {interface_name}: {str(e)}"

def verify_input_containers(user_equipments):
    
    container_names = containers_check()

     # Verifica se tutti i parametri in user_equipments sono presenti in container_names
    if all(ue in container_names for ue in user_equipments):
        print("Container trovati in user_equipments:")
        for ue in user_equipments:
            if ue in container_names:
                print(ue)
    else:
        # Almeno uno dei parametri non è presente, mostra un messaggio di errore
        raise Exception("Errore: uno o più nomi di container specificati non sono presenti nella lista dei container.")
    
    return True

def latency_test(user_equipments, concurrent = False):

    print("\n*** Latency test running ping to google.com")

    try:
        verify_input_containers(user_equipments)
    except Exception as e:
        print(e)
        return

    ue_interfaces_dictionary = check_interfaces(user_equipments)
    
    upfs_ip = get_upfs_ip()

    # Create a list to store the ping threads
    ping_threads = []

    # Define a function to run ping and store the result
    def run_ping_and_store_result(ue, interface_name, destination, results):
        result = run_ping(ue, interface_name, destination)
        results[(ue, interface_name)] = result

    # Create a dictionary to store ping results
    ping_results = {}

    # Iterate through container names and interfaces
    for ue in ue_interfaces_dictionary:
        print(f"Running ping in {ue}")
        for index, interface_name in enumerate(ue_interfaces_dictionary[ue]):
            destination = upfs_ip[index]
            print(f"Running ping in {interface_name},{destination}")
            if concurrent:
                # Create a thread to run ping and store the result
                thread = threading.Thread(target=run_ping_and_store_result, args=(ue, interface_name, destination, ping_results))
                thread.start()  # Start the thread
                ping_threads.append(thread)
            else:
                run_ping_and_store_result(ue, interface_name, destination, ping_results)

    if concurrent:
        # Wait for all ping threads to complete
        for thread in ping_threads:
            thread.join()


    # Print ping results
    print("\n*** Ping Results")
    for (ue, interface_name), result in ping_results.items():
        print(f"Container: {ue}, Interface: {interface_name}")
        print(result)
        print("=" * 60)
