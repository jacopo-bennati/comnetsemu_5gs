import subprocess
import re
import time
import sys
import os
from tabulate import tabulate 
import threading
from python_modules.Open5GS import Open5GS 

# Maximum number of retries
MAX_TRY = 3
# Corresponds to the number of ogstuns in upfs, therefore the upfs number
INTERFACE_PER_UE = 2
# Default destination for connectivity test 
CONN_TEST_DEST = "www.google.com"
# UPF macros
UPF_MEC = "upf_mec"
UPF_CLD = "upf_cld"
MEC_SERVER_IP = "192.168.0.135"
# Open5GS
O5GS   = Open5GS( "172.17.0.2" ,"27017")

# Print a list of available commands
def help():
    print("\tAvailable Commands:")
    print("\t\tshow details - Display details")
    print("\t\tlatency - Run the latency test")
    print("\t\tbandwidth - Run the bandwidth test")
    print("\t\tnodes - Prints crossed nodes")
    print("\t\texit - Exit the program")
    print("\t\tclear - Clear the shell")

# Convert a list to a string with regex
def from_list_to_string_with_regex(regexp, lst):
    string = ""

    # Check if active containers were found
    if lst:
        # Join container names into a single string separated by commas
        string = " ".join(lst)
    else:
        print("Empty list.")
    
    return re.findall(regexp, string)

def get_ue_dictionary(ue_containers):
    subscribers_imsi = O5GS.getSubscribersImsiList()
    user_equipments = {}
    imsi_list = []

    for retry in range(MAX_TRY):
        try:
            for ue_container in ue_containers:
                user_equipments[ue_container] = dump_imsi_in_container(ue_container)
                for imsi in user_equipments[ue_container]:
                    imsi_list.append(imsi)

            # Check if IMSI registration is correct 
            if len(imsi_list) == len(subscribers_imsi):
                break
            else:
                print(f"[\u2717] Waiting IMSI registration. Retrying in 15 seconds...")
                time.sleep(15)

        except Exception as e:
            print(f"An error occurred: {str(e)}. Retrying in 15 seconds...")
            time.sleep(15)
            
    if len(imsi_list) != len(subscribers_imsi):
        print(f"[\u2717] Unable to get the list of IMSI after {MAX_TRY} attempts.")
        sys.exit(1)

    return user_equipments

def get_ue_list(user_equipments):
    user_equipments_list = {}
    for key, values in user_equipments.items():
        user_equipments_list[key] = list(range(1, len(values) + 1))
    return user_equipments_list

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

def environment_check():
    container_names = containers_check()

    # Check if active containers were found
    if container_names:
        # Join container names into a single string separated by commas
        container_names_str = " ".join(container_names)
        print(f"Containers found: {container_names_str}")
    else:
        print("No active containers found; make sure you have started a network topology.")
        exit(1)
    
    return container_names

def dump_imsi_in_container(user_equipment):
    # Execute 'docker exec' to enter the container
    command = f"docker exec {user_equipment} ./nr-cli --dump | cut -d'-' -f2"
    
    imsi_list = None
    imsi_output = subprocess.check_output(command, shell=True, universal_newlines=True)
    imsi_list = imsi_output.splitlines()  # Extract IMSI from the output string
    
    return imsi_list

def get_subscriptions_dictionary(ue_details):
    subscribers_info = O5GS._GetSubscribers()

    print("*** Creating a dictionary with UE subscription details")

    # Create a dictionary to associate IMSIs with slice details
    subscription_details = {}

    try:
        for ue_container, inner_ues in ue_details.items():
            for inner_ue, data in inner_ues.items():
                imsi = data['imsi']
                # Search for IMSI in the subscriber list and store slice details
                for subscriber in subscribers_info:
                    if imsi in subscriber['imsi']:
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
                        
                        subscription_details[f'{ue_container}[{inner_ue}]'] = {
                            'imsi': subscriber['imsi'],
                            'slice_details': slice_details
                        }
                        
    except Exception as e:
        print(f"An error occurred for container: {str(e)}")
    
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
        print(f"Error: Unknown upf called: 'upf_{name}'")
    upf_ip = subprocess.check_output(command, shell=True, universal_newlines=True)
    return upf_ip

def get_supi_detail_from_smf_log(subscribers_info):
    script_path = os.path.abspath(__file__)
    prj_folder = os.path.dirname(script_path)
    data = {}
    supi_pattern = re.compile(r'UE SUPI\[imsi-(\d+)\] DNN\[(\w+)\] IPv4\[([\d.]+)\] IPv6\[\]')
    while True:
        try:
            with open(f'{prj_folder}/log/smf.log', 'r') as log_file:
                for line in log_file:
                    match = supi_pattern.search(line)
                    if match:
                        imsi = match.group(1)
                        dnn = match.group(2)
                        ip = match.group(3)
                        if imsi not in data:
                            data[imsi] = {}
                        data[imsi][dnn] = ip

                if len(data) == len(subscribers_info):
                    break

                print("[\u2717] SMF is not ready. Waiting 10 seconds...")
                time.sleep(10)

        except FileNotFoundError:
            print("[\u2717] SMF is not ready. Waiting 10 seconds...")
            time.sleep(10)
            continue
        except Exception as e:
            print(f"[\u2717] An error occurred while reading the log file: {str(e)}")
            sys.exit(1)

    sorted_data = {key: data[key] for key in sorted(data.keys())}
    return sorted_data

def get_interface_ip_dict(ue_container):
    command = f"docker exec {ue_container} ifconfig"
    ifconfig_output = subprocess.check_output(command, shell=True, universal_newlines=True)
    interfaces = re.findall(r"(\buesimtun\d): flags=", ifconfig_output)
    ips = re.findall(r"inet (\S+)", ifconfig_output)
    ips = [ip for ip in ips if re.match(r"^10\.", ip)]

    interface_ip_dict = dict(zip(ips, interfaces))
    return interface_ip_dict

def check_interfaces(ue_containers):
    """Creates a dictionary with UE details with reference to IPs and interfaces of each slice of each IMSI.
    Also performs DN reachability."""

    print(f"*** Checking interfaces")    
    
    subscribers_imsi = O5GS.getSubscribersImsiList()
    ue_details = {}
    
    imsi_dn_ips_dict = get_supi_detail_from_smf_log(subscribers_imsi)
    subscribers_info = O5GS._GetSubscribers()

    for ue_container, inner_ues in ue_containers.items():
        ue_details[ue_container] = {}
        for retry in range(MAX_TRY):
            try:
                
                interface_ip_dict = get_interface_ip_dict(ue_container)
                
                current_dict = {}
                
                for inner_ue_imsi in inner_ues:
                    current_dict[inner_ue_imsi] = imsi_dn_ips_dict[inner_ue_imsi]
                
                for index, (imsi, data) in enumerate(current_dict.items(), start=1):
                    
                    slice_data = []
                    
                    for dnn, ip in data.items():
                        slice_data.append({
                            'dnn': dnn,
                            'ip': ip,
                            'interface': interface_ip_dict[ip]
                        })

                    ue_details[ue_container][index] = {
                        'imsi': imsi,
                        'slice': slice_data
                    }

                interfaces_found = True

                for key, ue in ue_details[ue_container].items():
                    ue_details_imsi = ue['imsi']
                    ue_details_interfaces = ue['slice']

                    subscriber_info_interfaces = None
                    for subscriber in subscribers_info:
                        if subscriber['imsi'] == ue_details_imsi:
                            subscriber_info_interfaces = subscriber['slice']
                            break
                                
                    if subscriber_info_interfaces is not None and len(ue_details_interfaces) == len(subscriber_info_interfaces):
                        break    
                    else:
                        interfaces_found = False
                
                if interfaces_found:
                    break
                else:
                    print(f"[\u2717] {ue_container}: inactive interfaces, retrying in 10 seconds...")
                    time.sleep(10)

            except Exception as e:
                print(f"An error occurred for container {ue_container}: {str(e)}")
                sys.exit(1)
                
        if retry == MAX_TRY:
            print(f"[\u2717] {ue_container}")
            print(f"Error: Interfaces are inactive in {ue_container}.")
            print(f"Note that if you just started the topology, it might take some time to set up the interfaces correctly, depending on network complexity.")
            sys.exit(1)
            
                
    # Run connectivity test
    for container, inner_ue_data in ue_details.items():
        print(f"°°° {container}")
        # iterate through each inner UE data
        for index, inner_ue_details in inner_ue_data.items():
            # iterate through each slice
            for slice in inner_ue_details['slice']:
                # extract slice data
                dnn = slice['dnn']
                ip = slice['ip']
                interface = slice['interface']
                destination = MEC_SERVER_IP if dnn == "mec" else CONN_TEST_DEST
                try:
                    # run ping
                    ping_result = run_ping(container, interface, destination, 3)
                except RuntimeError as re:
                    print(re)
                    sys.exit(1)
                except Exception as e:
                    print(f"An error occurred for container {container} and interface {interface}:\n{str(e)}")
                    sys.exit(1)
                
                # Analyze the output of the command
                if "100% packet loss" in ping_result:
                    if dnn == "mec":
                        print(f"[\u2717] {container}[{index}] [{interface}]: MEC server not reachable")
                    else:
                        print(f"[\u2717] {container}[{index}] [{interface}]: DN not reachable")
                else:
                    if dnn == "mec":
                        print(f"[\u2713] {container}[{index}] [{interface}]: MEC server reachable")
                    else:
                        print(f"[\u2713] {container}[{index}] [{interface}]: DN reachable")
    return ue_details

def capture_packets(tshark_interface, timeout, nodes):
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

def run_ping(container_name, interface_name, destination, packet=10):
    """Define a function to run a ping command and capture the output"""

    try:
        # print(f"Running ping in {container_name} using interface {interface_name}")
        # Run the ping command inside the container
        command = f"docker exec {container_name} ping -c {packet} -n -I {interface_name} {destination}"
        ping_output = subprocess.check_output(command, shell=True, universal_newlines=True)
        
        # Use a regular expression to find the ping statistics section
        pattern = re.compile(rf'--- {re.escape(destination)} ping statistics ---\n(.*?)$\n', re.DOTALL)
        match = pattern.search(ping_output)
        
        if match:
            ping_statistics = match.group(1)  # Get the ping statistics part
            return ping_statistics
        else:
            raise RuntimeError(f"Unable to find ping statistics for container {container_name} and interface {interface_name}")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"An error occurred for container {container_name} and interface {interface_name}:\n{str(e)}")

def latency_test(user_equipments_to_test, ue_details, concurrent=False):
    # print("\n*** Latency test")

    # Create a list to store the ping threads
    ping_threads = []

    # Define a function to run ping and store the result
    def run_ping_and_store_result(user_equipment, ue_index, interface_name, destination, results):
        try:
            result = run_ping(user_equipment, interface_name, destination)
        except RuntimeError as re:
            print(re)
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred for container {user_equipment} and interface {interface}:\n{str(e)}")
            sys.exit(1)
        results[(user_equipment, ue_index, interface_name, destination)] = result

    # Create a dictionary to store ping results
    ping_results = {}
    
    # Initial assignment 
    upfs_ip = {'internet': get_upf_ip(UPF_CLD), 'mec': get_upf_ip(UPF_MEC) }
    
    for ue, indices in user_equipments_to_test.items():
        print(f"Running ping for {ue}:")
        for ue_index in indices:
            print(f"\tInner UE ({ue_index})")
            slices = ue_details[ue][ue_index]['slice']
            for slice in slices:
                dnn = slice['dnn']
                interface = slice['interface']
                ip = slice['ip']
                destination = upfs_ip[dnn]
                if concurrent:
                    # Create a thread to run ping and store the result
                    _target = run_ping_and_store_result
                    _args = (ue, ue_index, interface, destination, ping_results)
                    thread = threading.Thread(target=_target, args=_args)
                    thread.start()  # Start the thread
                    ping_threads.append(thread)
                else:
                    try:
                        result = run_ping(ue, interface, destination)
                    except RuntimeError as re:
                        print(re)
                        sys.exit(1)
                    except Exception as e:
                        print(f"An error occurred for container {ue} and interface {interface}:\n{str(e)}")
                        sys.exit(1)
                    ping_results[(ue, ue_index, interface, destination)] = result

    if concurrent:
        # Wait for all ping threads to complete
        for thread in ping_threads:
            thread.join()
            
    
    print_latency_result(upfs_ip, ping_results)

def print_latency_result(upfs_ip, data):
    
    pattern = re.compile(r'rtt min/avg/max/mdev = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+) ms')
    
    table = []
    
    headers = ["UE", "interface", "destination", "min_rtt", "avg_rtt", "max_rtt", "mdev_rtt"]
    
    for (ue, ue_index, interface, destination), result in data.items():
        ping_output_lines = result.split('\n')
        ping_rtt = ping_output_lines[1]
        if destination == upfs_ip['internet']:
            dest_name = UPF_CLD
        else:
            dest_name = UPF_MEC
        
        ue_label = f'{ue}[{ue_index}]'
        interface_label = interface
        destination_label = dest_name
        
        match = pattern.search(ping_rtt)

        # If a match is found, extract the values and create a dictionary
        if match:
            min_rtt, avg_rtt, max_rtt, mdev_rtt = map(float, match.groups())
            
        table.append([ue_label, interface_label, destination_label, min_rtt, avg_rtt, max_rtt, mdev_rtt])
    
    print(tabulate(table, headers=headers, tablefmt="grid"))
    
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

        # Initialize variables to track IP addresses
        client_ip = None
        server_ip = None

        # Extract IP addresses
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

        # Extract transfer data
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
    """Define a function to run an iperf3 command and capture the output"""
    try:
        command = f"docker exec {ue} ifconfig {interface} | awk '/inet / {{print $2}}' | tr -d '\n'"
        ue_upf_ip = subprocess.check_output(command, shell=True, universal_newlines=True)

        command = f"docker exec {ue} iperf3 -c {destination} -B {ue_upf_ip} -t 15"
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        
        return extract_bandwidth_data(output=output)
    
    except Exception as e:
        return f"An error occurred for container {ue}: {str(e)}"

def bandwidth_test(user_equipments_to_test, ue_details):
    # Create a dictionary to store bandwidth results
    bandwidth_results = {}
    
    # Initial assignment 
    upfs_ip = {'internet': get_upf_ip(UPF_CLD), 'mec': get_upf_ip(UPF_MEC)}
    
    for ue, indices in user_equipments_to_test.items():
        print(f"Running iperf3 for {ue}:")
        for ue_index in indices:
            print(f"\tInner UE ({ue_index})")
            slices = ue_details[ue][ue_index]['slice']
            for slice in slices:
                dnn = slice['dnn']
                interface = slice['interface']
                ip = slice['ip'] 
                destination = upfs_ip[dnn]
                destination_name = UPF_CLD if dnn=='internet' else UPF_MEC
                result = run_iperf3(ue, interface, destination)
                bandwidth_results[(ue, ue_index, interface, destination_name)] = result

    # Print bandwidth results
    print("\n*** Bandwidth Results")
    print_bandwidth_result(bandwidth_results)

def capture_packets(tshark_interface, timeout, nodes):
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
    """
    Displays information about network nodes for each user equipment and interface.

    :param user_equipments_to_test: Dictionary containing user equipment information.
    :param ue_details: Detailed information about user equipment, including slices and interfaces.
    """

    # List of Tshark interfaces to check for nodes
    tshark_interfaces = ["s1-gnb1", "s1-gnb2", "s3-upf", "s2-upf_mec"]
    
    # Timeout for Tshark capture in seconds
    timeout = 2.5
    
    # List to store thread objects
    threads = []
    
    # Dictionary to store Tshark results
    tshark_result = {}
        
    for ue, indices in user_equipments_to_test.items():
        for ue_index in indices:
            print(f"Checking nodes for {ue}[{ue_index}]")
            
            # Extract slices information
            slices = ue_details[ue][ue_index]['slice']
            
            for slice in slices:
                # Extract interface information
                interface = slice['interface']
                
                # Lists to store raw and formatted node information
                node_list = []
                formatted_node_list = []
                
                # Iterate through Tshark interfaces and run capture_packets and run_ping in separate threads
                for tshark_interface in tshark_interfaces:
                    tshark_thread = threading.Thread(target=capture_packets, args=(tshark_interface, timeout, node_list))
                    tshark_thread.start()
                    threads.append(tshark_thread)
                    
                    ping_thread = threading.Thread(target=run_ping, args=(ue, interface, CONN_TEST_DEST))
                    ping_thread.start()
                    threads.append(ping_thread)

                # Wait for all Tshark threads to finish
                for thread in threads:
                    thread.join()
                
                # Sort and format node_list
                node_list = sorted(node_list)
                
                # Function to format node names
                def format_node(node):
                    matches = re.findall(r'(gnb\d+|upf(_mec)?)', node)
                    return matches[0][0]
                
                # Apply formatting and store results in formatted_node_list
                for node in node_list:
                    formatted_node = format_node(node)
                    formatted_node_list.append(formatted_node)
                
                # Store formatted_node_list in tshark_result dictionary
                tshark_result[(ue, ue_index, interface)] = formatted_node_list

    # Print nodes results
    print("\n*** Nodes")
    data = []
    for ((ue, index, interface), nodes) in tshark_result.items():
        ue_label = f"{ue}[{index}]"
        data.append((ue_label, interface, nodes))
    
    # Convert data to a table and print
    table = tabulate(data, headers=["UE", "Interface", "Nodes"], tablefmt="grid")
    print(table)
