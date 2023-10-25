import subprocess
import re
import time
import sys
import json
import os
from tabulate import tabulate 
import threading
import subprocess
import asyncio 

# Massima quantità di tentativi
MAX_RETRY = 3
# Corresponds to number of ogstuns in upfs, therefore upfs number
INTERFACE_PER_UE = 2
# Default destination for connectivity test 
CONN_TEST_DEST = "www.google.com"
# upfs macros
UPF_MEC = "upf_mec"
UPF_CLD = "upf_cld"

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

def get_ue_dictionary(ue_containers):
    
    user_equipments = {}
    
    inner_ues = 0
    
    for ue_container in ue_containers:
        inner_ues = len(dump_imsi_in_container(ue_container))
        user_equipments[ue_container] = []
        for index in range(inner_ues):
            user_equipments[ue_container].append(index+1)
            
    return user_equipments

def containers_check():

    print(f"*** Checking containers")

    # Execute the 'docker ps' command and capture the output
    try:
        output = subprocess.check_output(["docker", "ps"]).decode("utf-8")
    except subprocess.CalledProcessError:
        print("Error executing 'docker ps'. Make sure Docker is running.")
        exit(1)

    # Find container names similar to 'ue_n'
    user_equipments = re.findall(r'(\bue\d+\b)', output)
    base_stations = re.findall(r'(\bgnb\d+\b)', output)
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

def dump_imsi_in_container(user_equipment):
    # Execute 'docker exec' to enter the container
    command = f"docker exec {user_equipment} ./nr-cli --dump | cut -d'-' -f2"
    imsi_output = subprocess.check_output(command, shell=True, universal_newlines=True)
    imsi = imsi_output.splitlines()  # Extract IMSI from the output string
    return imsi

def get_subscriptions_dictionary(ues_container):
    
    subscribers_info = get_subscriber_info()

    print("*** Creating a dictionary with UE subscription details")

    # Create a dictionary to associate IMSIs with slice details
    subscription_details = {}

    # Iterate through UE container names
    for ue_container in ues_container:
        for retry in range(MAX_RETRY):
            try:
                imsi = dump_imsi_in_container(ue_container)
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
                        
                        subscription_details[f'{ue_container}[{index}]'] = {
                            'imsi': subscriber['imsi'],
                            'slice_details': slice_details
                        }
                
                # Check if imsi is present in the output
                if imsi:
                    print(f"\t[\u2713] {ue_container}: active and operating")
                    break  # Imsi obtained, no need to retry

                # If it's the last retry, exit with an error message
                if retry == MAX_RETRY:
                    print(f"[\u2717] Unable to obtain IMSI from {ue_container}")
                    print(f"Note that if you just started the topology it might take at least 30s to setup correctly the User equipments (or more depending on network complexity)  ")
                    exit(1)

                # If not the last retry, wait for 5 seconds before retrying
                print(f"[\u2717] Unable to obtain IMSI from {ue_container}, retrying in 15 seconds...")
                time.sleep(15)
                
            except Exception as e:
                print(f"An error occurred for container {ue_container}: {str(e)}")
    
    return subscription_details

def print_sub_detail_table(subscription_details):
    # Building the table using tabulate

    print("*** Printing Slice/Service Type details per subscriber ")

    # Define table headers
    headers = ["Name", "IMSI", "SST 1", "Downlink/Uplink 1", "SST 2", "Downlink/Uplink 2"]

    # Create a list for table data
    table_data = []

    # Create a dictionary to keep track of rows for each user/IMSI
    user_rows = {}

    for user_equipment, details in subscription_details.items():
        imsi = details["imsi"]
        if imsi not in user_rows:
            user_rows[imsi] = {
                "Name": user_equipment,
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

def get_upf_ip(name):
    upf_ip = "0.0.0.0"
    if name == UPF_CLD:
        command = "docker exec upf_cld ifconfig ogstun | awk '/inet / {print $2}'| tr -d '\n'"
    elif name == UPF_MEC:
        command = "docker exec upf_mec ifconfig ogstun | awk '/inet / {print $2}' | tr -d '\n'"
    else:
        print(f"Error: Unknown upf called : 'upf_{name}'")
    upf_ip = subprocess.check_output(command, shell=True, universal_newlines=True)
    return upf_ip

def check_interfaces(container_names):
    # Check if interfaces are configured correctly

    print(f"*** Checking interfaces")    
    
    ue_details = {}

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
                interface_info = sorted(interface_info, key=lambda x: int(x[0].lstrip("uesimtun")))
                
                inner_ue_detail = {}
                
                interfaces = {}
                
                # from 0 to upf number 
                target = 1
                
                for inner_ue, (interface, ip) in enumerate(interface_info, start=1):
                    interfaces[interface] = ip
                    # EVEN, each two iterfaces since there are two upfs
                    if inner_ue % 2 == 0:
                        inner_ue_detail[target] = interfaces.copy()
                        interfaces.clear()
                        target += 1
                
                ue_details[container_name] = inner_ue_detail
                        
                # If it's the last retry, exit with an error message
                if retry == MAX_RETRY:
                    print(f"[\u2717] {container_name}")
                    print(f"Error: Interfaces are inactive in {container_name}.")
                    print(f"Note that if you just started the topology it might take some time to setup correctly the interfaces depending on network complexity")
                    raise Exception("Interface issues")
                else:
                    break
            except Exception as e:
                print(f"An error occurred for container {container_name}: {str(e)}")
                sys.exit(1)
                
    # Run connectivity test
    for container, inner_ue_data in ue_details.items():
        print(f"°°° {container}:")
        for index, inner_ue in inner_ue_data.items():
            for interface, ip in inner_ue.items():
                ping_result = run_ping(container, interface, CONN_TEST_DEST)
                if "100% packet loss" in ping_result:
                    print(f"[\u2717] {container}[{index}] [{interface}]: DN not reachable")
                else:
                    print(f"[\u2713] {container}[{index}] [{interface}]: DN reachable")
    return ue_details

def capture_packets(tshark_interface,timeout,nodes):
    result = None
    try:
        command = f"sudo tshark -i {tshark_interface} -Y 'icmp' -a duration:{timeout}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        result = stdout.decode('utf-8')
        if result != '':
            nodes.append(tshark_interface)
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def run_ping(container_name, interface_name, destination):
    """Define a function to run a ping command and capture the output"""

    try:
        # print(f"Running ping in {container_name} using interface {interface_name}")
        # Run the ping command inside the container
        command = f"docker exec {container_name} ping -c 3 -n -I {interface_name} {destination}"
        ping_output = subprocess.check_output(command, shell=True, universal_newlines=True)
        
        # Use a regular expression to find the ping statistics section
        pattern = re.compile(rf'--- {re.escape(destination)} ping statistics ---\n(.*?)$\n', re.DOTALL)
        match = pattern.search(ping_output)
        
        if match:
            ping_statistics = match.group(1)  # Get the ping statistics part
            return ping_statistics
        else:
            return f"Unable to find ping statistics for container {container_name} and interface {interface_name}"
    except Exception as e:
        return f"An error occurred for container {container_name} and interface {interface_name}: {str(e)}"

def latency_test(user_equipments_to_test, ue_details, concurrent = False):
    #print("\n*** Latency test")

    # Create a list to store the ping threads
    ping_threads = []

    # Define a function to run ping and store the result
    def run_ping_and_store_result(user_equipment, interface_name, destination, results):
        result = run_ping(user_equipment, interface_name, destination)
        results[(user_equipment, interface_name, destination)] = result

    # Create a dictionary to store ping results
    ping_results = {}
    
    # Initial assignment 
    upfs_ip = [get_upf_ip(UPF_CLD), get_upf_ip(UPF_MEC)]
    
    for ue, indices in user_equipments_to_test.items():
        print(f"Running ping for {ue}:")
        for index in indices:
            print(f"\tInner UE ({index})")
            interfaces = ue_details[ue][index]
            for count, (interface, ip) in enumerate(interfaces.items()):
                destination = upfs_ip[count%2]
                if concurrent:
                    # Create a thread to run ping and store the result
                    _target = run_ping_and_store_result
                    _args=(ue, interface, destination, ping_results)
                    thread = threading.Thread(target = _target, args = _args)
                    thread.start()  # Start the thread
                    ping_threads.append(thread)
                else:
                    result = run_ping(ue, interface, destination)
                    ping_results[(ue, interface, destination)] = result

    if concurrent:
        # Wait for all ping threads to complete
        for thread in ping_threads:
            thread.join()

    # Print ping results
    print("\n*** Ping Results")
    for (ue, interface_name, destination), result in ping_results.items():
        ping_output_lines = result.split('\n')
        ping_rtt = ping_output_lines[1]
        if destination == upfs_ip[0]:
            dest_name = UPF_CLD
        else:
            dest_name = UPF_MEC
        print(f"Container: {ue}, Interface: {interface_name}, Destination: {dest_name}")
        print(ping_rtt)
        print("_" * 60)
        print("")

def print_bandwidth_result(data):
    
    table = []

    for (ue, index, interface, destination_name), values in data.items():
        for (client, host, [sender, receiver]) in values:
            ue_label = f'{ue}[{index}]'
            interface_label = f'{interface}[{client}]'
            destination_label = f'{destination_name}[{host}]'
            table.append([ue_label, interface_label, destination_label, sender, receiver])

    headers = ["UE", "interface", "destination", "sender(Mbits/sec)", "receiver(Mbits/sec)"]

    print(tabulate(table, headers=headers, tablefmt="grid"))

def extract_bandwidth_data(output):
    try:
        results = []

        lines = output.strip().split('\n')

        # Inizializzo le variabili per tenere traccia degli indirizzi IP
        client_ip = None
        server_ip = None

        # Estraggo gli indirizzi IP
        for line in lines:
            client_match = re.search(r'local (\d+\.\d+\.\d+\.\d+)', line)
            if client_match:
                client_ip = client_match.group(1)
            server_match = re.search(r'Connecting to host (\d+\.\d+\.\d+\.\d+),', line)
            if server_match:
                server_ip = server_match.group(1)

            if client_ip and server_ip:
                break

        if not (client_ip and server_ip):
            raise Exception('Connection information not found')

        # Estraggo i dati di trasferimento
        transfer_data = []
        for line in lines:
            columns = line.split()
            if "receiver" in line or "sender" in line:
                transfer_data.append(columns[6])
        
        results.append((client_ip, server_ip, transfer_data))

        return results
    
    except Exception as e:
        return f"An error occurred: {str(e)}"

def run_iperf3(ue, interface, destination):
    """Define a function to run a iperf3 command and capture the output"""
    try:
        command = f"docker exec {ue} ifconfig {interface} | awk '/inet / {{print $2}}' | tr -d '\n'"
        ue_upf_ip = subprocess.check_output(command, shell=True, universal_newlines=True)

        command = f"docker exec {ue} iperf3 -c {destination} -B {ue_upf_ip} -t 5"
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        
        return extract_bandwidth_data(output=output)
    
    except Exception as e:
        return f"An error occurred for container {ue}: {str(e)}"

def bandwith_test(user_equipments_to_test, ue_details):
    # Create a dictionary to store bandwidth results
    bandwidth_results = {}
    
    # Initial assignment 
    upfs_ip = [get_upf_ip(UPF_CLD), get_upf_ip(UPF_MEC)]
    
    for ue, indices in user_equipments_to_test.items():
        print(f"Running iperf3 for {ue}:")
        for index in indices:
            print(f"\tInner UE ({index})")
            interfaces = ue_details[ue][index]
            for count, (interface, ip) in enumerate(interfaces.items()):
                destination = upfs_ip[count%2]
                destination_name = UPF_CLD if (count%2) == 0 else UPF_MEC
                result = run_iperf3(ue, interface, destination)
                bandwidth_results[(ue, index, interface, destination_name)] = result

    # Print bandwidth results
    print("\n*** Bandwidth Results")
    print_bandwidth_result(bandwidth_results)

def capture_packets(tshark_interface,timeout,nodes):
    result = None
    try:
        command = f"sudo tshark -i {tshark_interface} -Y 'icmp' -a duration:{timeout}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        result = stdout.decode('utf-8')
        if result != '':
            nodes.append(tshark_interface)
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def show_nodes(user_equipments_to_test, ue_details):

    tshark_interfaces = ["s1-gnb1", "s1-gnb2", "s3-upf", "s2-upf_mec"]
    timeout = 2
    tshark_threads = []
    tshark_result = {}
        
    for ue, indices in user_equipments_to_test.items():
        for ue_index in indices:
            print(f"Checking nodes for {ue}[{ue_index}]")
            slices = ue_details[ue][ue_index]['slice']
            for slice in slices:
                interface = slice['interface']
                nodes = []
                for tshark_interface in tshark_interfaces:
                    tshark_thread = threading.Thread(target=capture_packets, args=(tshark_interface, timeout, nodes))
                    tshark_thread.start()
                    tshark_threads.append(tshark_thread)

                    result = run_ping(ue, interface, 'www.google.com')

                # Attendi che tutti i thread di tshark terminino
                for tshark_thread in tshark_threads:
                    tshark_thread.join()
                
                tshark_result[(ue, index, interface)] = nodes

    # Print nodes results
    print("\n*** Nodes")
    data = []
    for ((ue, index, interface), nodes) in tshark_result.items():
        ue_label = f"{ue}[{index}]"
        data.append((ue_label, interface, nodes))
    # Converte i dati in una tabella
    table = tabulate(data, headers=["UE", "Interface", "Nodes"], tablefmt="grid")
    print(table)