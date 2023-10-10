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
    user_equipments = re.findall(r'(\bue+\b)', output)
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
                imsi = imsi_output.splitlines()  # Extract IMSI from the output string

                # Search for IMSI in the JSON file and store slice details
                for index, subscriber in enumerate(subscribers_info['subscribers'], start=1):
                    if subscriber['imsi'] in imsi:
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
                        
                        ue_details[f'{container_name}[{index}]'] = {
                            'imsi': subscriber['imsi'],
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

# ---

def check_interfaces(container_names, ue_details):
    # Check if interfaces are configured correctly

    print(f"*** Checking interfaces")

    print(f"Interfaces state:")

    for container_name in container_names:
        for retry in range(MAX_RETRY + 1):
            try:
                # Run the 'ifconfig' command inside the container
                command = f"docker exec {container_name} ifconfig"
                ifconfig_output = subprocess.check_output(command, shell=True, universal_newlines=True)
                interfaces = re.findall(r"(\buesimtun\d): flags=", ifconfig_output)
                ips = re.findall(r"inet (\S+)", ifconfig_output)
                ips = [ip for ip in ips if re.match(r"^10\.", ip)]
                interface_info = list(zip(interfaces, ips))
                interface_info = sorted(interface_info, key=lambda x: [int(i) for i in x[1].split('.')])

                for index in range(int((interface_info.__len__()/2))):
                    i = 1
                    if (index+i) > (interface_info.__len__() - 1):
                                i = -index
                    while (interface_info[index][1][8] != interface_info[index+i][1][8]):
                            # print(i)
                            # print(f"[{interface_info[index][0]}, {interface_info[index][1][8]}], [{interface_info[index+i][0]}, {interface_info[index+i][1][8]}]")
                            i += 1
                            if (index+i) > (interface_info.__len__() - 1):
                                i = -index
                    ue_details[f'ue[{index+1}]']['interfaces'] = {
                            interface_info[index][0]: interface_info[index][1],
                            interface_info[index + i][0]: interface_info[index + i][1]
                        }

                # If it's the last retry, exit with an error message
                if retry == MAX_RETRY:
                    print(f"[\u2717] {container_name}: inactive")
                    print(f"Error: Interfaces are inactive in {container_name}.")
                    print(f"Note that if you just started the topology it might take at least 30s to setup correctly the interfaces (or more depending on network complexity)")
                    raise Exception("Interface issues")
                else:
                    print(interface_info)
                    # Check if 'uesimtun0' and 'uesimtun1' interfaces are present in the output
                    for interface in interface_info:
                        print(f"[\u2713] {interface[0]}[{interface[1]}]: active")
                    return ue_details

            except Exception as e:
                print(f"An error occurred for container {container_name}: {str(e)}")
                sys.exit(1)

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

def latency_test(user_equipments, ue_details, concurrent = False):

    print("\n*** Latency test running ping to google.com")

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

    ue_details = check_interfaces(user_equipments, ue_details)

    # Create a list to store the ping threads
    ping_threads = []

    # Define a function to run ping and store the result
    def run_ping_and_store_result(ue, interface_name, destination, results):
        result = run_ping(ue, interface_name, destination)
        results[(ue, interface_name)] = result

    # Create a dictionary to store ping results
    ping_results = {}

    # Iterate through container names and interfaces
    for user_e, detail in ue_details.items():
        print(f"Running ping in {user_e}")
        for interface, ip in ue_details[str(user_e)]['interfaces'].items():
            container = re.sub(r'\[.*?\]', '', user_e)
            if concurrent:
                # Create a thread to run ping and store the result
                thread = threading.Thread(target=run_ping_and_store_result, args=(container, interface, ping_results))
                thread.start()  # Start the thread
                ping_threads.append(thread)
                thread = threading.Thread(target=run_ping_and_store_result, args=(container, interface, ping_results))
                thread.start()  # Start the thread
                ping_threads.append(thread)
            else:
                result = run_ping(container, interface)
                ping_results[(user_e, interface)] = result
                result = run_ping(container, interface)
                ping_results[(user_e, interface)] = result

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

def print_bandwidth_result(data):
    table = []
    for ue, values in data.items():
        for host, (sender, receiver) in values:
            table.append([ue, host, sender, receiver])

    headers = ["UE", "HOST", "sender(Mbits/sec)", "receiver(Mbits/sec)"]

    print(tabulate(table, headers=headers, tablefmt="grid"))

def extract_bandwidth_data(output):
    results = []

    # Divido l'output in blocchi separati per ogni connessione
    blocks = re.split(r'iperf Done\.', output)

    for block in blocks:
        lines = block.strip().split('\n')
        
        if len(lines) < 3:
            continue

        # Estraggo l'indirizzo IP dell'host
        ip_match = re.search(r'Connecting to host (\d+\.\d+\.\d+\.\d+), port \d+', lines[0])
        if ip_match:
            ip = ip_match.group(1)
        else:
            continue

        # Estraggo i dati di trasferimento
        transfer_data = []
        for line in lines:
            columns = line.split()
            if "receiver" in line or "sender" in line:
                transfer_data.append(columns[4])
        
        results.append((ip, transfer_data))

    return results

# Define a function to run a iperf3 command and capture the output
def run_iperf3(container_name):
    try:
        command = "docker exec upf_mec ifconfig ogstun | awk '/inet / {print $2}' | tr -d '\n'"
        upf_mec_ip = subprocess.check_output(command, shell=True, universal_newlines=True)
        command = "docker exec upf_cld ifconfig ogstun | awk '/inet / {print $2}'| tr -d '\n'"
        upf_cld_ip = subprocess.check_output(command, shell=True, universal_newlines=True)
        command = f"docker exec {container_name} ifconfig uesimtun0 | awk '/inet / {{print $2}}' | tr -d '\n'"
        ue_cld_ip = subprocess.check_output(command, shell=True, universal_newlines=True)
        command = f"docker exec {container_name} ifconfig uesimtun1 | awk '/inet / {{print $2}}'| tr -d '\n'"
        ue_mec_ip = subprocess.check_output(command, shell=True, universal_newlines=True)

        command = f"docker exec {container_name} iperf3 -c {upf_mec_ip} -B {ue_mec_ip} -t 5"
        mec_output = subprocess.check_output(command, shell=True, universal_newlines=True)
        command = f"docker exec {container_name} iperf3 -c {upf_cld_ip} -B {ue_cld_ip} -t 5"
        cld_output = subprocess.check_output(command, shell=True, universal_newlines=True)
        
        return extract_bandwidth_data(mec_output + cld_output)
    
    except Exception as e:
        return f"An error occurred for container {container_name}: {str(e)}"

def bandwith_test(user_equipments):

    print("\n*** Bandwith test running")

    container_names = containers_check()

     # Verifica se tutti i parametri in user_equipments sono presenti in container_names
    if all(ue in container_names for ue in user_equipments):
        print("Container trovati in user_equipments:")
        for ue in user_equipments:
            if ue in container_names:
                print(ue)
    else:
        # Almeno uno dei parametri non è presente, mostra un messaggio di errore
        print("Errore: uno o più nomi di container specificati non sono presenti nella lista dei container.")
        return

    check_interfaces(user_equipments)

    # Define a function to run bandwidth and store the result
    def run_iperf3_and_store_result(user_equipment, results):
        result = run_iperf3(user_equipment)
        results[(user_equipment)] = result

    # Create a dictionary to store bandwidth results
    bandwidth_results = {}

    # Iterate through container names and interfaces
    for user_equipment in user_equipments:
        print(f"Running iperf3 in {user_equipment}")
        result = run_iperf3(user_equipment)
        bandwidth_results[(user_equipment)] = result

    # Print bandwidth results
    print("\n*** Bandwidth Results")
    print_bandwidth_result(bandwidth_results)
    print("=" * 60)