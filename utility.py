import subprocess
import re
import time
import sys
import json
import os
from tabulate import tabulate 

# Massima quantità di tentativi
MAX_RETRY = 3


def evnironment_check():
     # Execute the 'docker ps' command and capture the output
    try:
        output = subprocess.check_output(["docker", "ps"]).decode("utf-8")
    except subprocess.CalledProcessError:
        print("Error executing 'docker ps'. Make sure Docker is running.")
        exit(1)

    # Find container names similar to 'ue_n'
    container_names = re.findall(r'(\bue_\d+\b)', output)

    # Sort the list in ascending order
    container_names.sort()

    # Check if active containers were found
    if container_names:
        # Join container names into a single string separated by commas
        container_names_str = " ".join(container_names)
        print(f"*** Containers found: {container_names_str}")
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

def check_interfaces(container_names):
    # Check if 'uesimtun0' and 'uesimtun1' interfaces are configured correctly

    print(f"Interfaces 'uesimtun0' and 'uesimtun1' state:")

    for container_name in container_names:
        for retry in range(MAX_RETRY):
            try:
                # Run the 'ifconfig' command inside the container
                command = f"docker exec {container_name} ifconfig"
                ifconfig_output = subprocess.check_output(command, shell=True, universal_newlines=True)

                # Check if 'uesimtun0' and 'uesimtun1' interfaces are present in the output
                if 'uesimtun0' in ifconfig_output and 'uesimtun1' in ifconfig_output:
                    print(f"[\u2713] {container_name}: active")
                    break  # Interfaces are active, no need to retry

                # If it's the last retry, exit with an error message
                if retry == MAX_RETRY:
                    print(f"[\u2717]{container_name}: inactive")
                    print(f"Error: Interfaces 'uesimtun0' and 'uesimtun1' are inactive in {container_name}.")
                    print(f"Note that if you just started the topology it might take at least 30s to setup correctly the interfaces (or more depending on network complexity)")
                    exit(1)

                # If not the last retry, wait for 5 seconds before retrying
                print(f"[\u2717] {container_name}: inactive, retrying in 15 seconds...")
                time.sleep(15)

            except Exception as e:
                print(f"An error occurred for container {container_name}: {str(e)}")

# Define a function to run a ping command and capture the output
def run_ping(container_name, interface_name):
    try:
        # print(f"Running ping in {container_name} using interface {interface_name}")
        # Run the ping command inside the container
        command = f"docker exec {container_name} ping -c 3 -n -I {interface_name} www.google.com"
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

def latency_test(container_names):

    print("\n*** Latency test running ping to google.com")

    # Create a dictionary to store ping results
    ping_results = {}

    # Iterate through container names and interfaces
    for container_name in container_names:
        print(f"Running ping in {container_name}")
        for interface_name in ['uesimtun0', 'uesimtun1']:
            result = run_ping(container_name, interface_name)
            ping_results[(container_name, interface_name)] = result

    # Print ping results
    print("\n*** Ping Results")
    for (container_name, interface_name), result in ping_results.items():
        print(f"Container: {container_name}, Interface: {interface_name}")
        print(result)
        print("=" * 40)
