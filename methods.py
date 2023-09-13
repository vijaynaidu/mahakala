import logging
import os
import subprocess
import json
import re
import ipaddress

def check_virtualenv():
    """
    Check if virtual environment is created.
    """
    if os.path.isdir("venv"):
        return True

    return False

def check_root():
    """
    Check if user is root.
    """
    if os.geteuid() == 0:
        return True

    return False

def check_iptables():
    """
    Check if iptables is installed.
    """
    try:
        subprocess.check_output(["iptables", "-V"])
        return True
    except:
        return False

def check_ip6tables():
    """
    Check if ip6tables is installed.
    """
    try:
        subprocess.check_output(["ip6tables", "-V"])
        return True
    except:
        return False

def load_meta_data(root):
    """
    Load metadata from a 'meta.json' file in a directory.

    Args:
        root (str): The directory path.

    Returns:
        dict: The metadata loaded from 'meta.json', or an empty dictionary if the file does not exist.
    """
    meta_file_path = os.path.join(root, 'meta.json')
    if os.path.exists(meta_file_path):
        with open(meta_file_path, 'r', encoding='latin-1') as meta_file:
            return json.load(meta_file)
    return {}

def process_ip_line(ip_line, source_name, result, line_no):
    """
    Process a line containing an IP address and update the result.

    Args:
        ip_line (str): The line containing an IP address.
        source_name (str): The name of the data source.
        result (dict): The result dictionary to update.
        line_no (int): The line number of the IP address.

    Returns:
        None
    """
    try:
        ip = ipaddress.ip_network(ip_line, strict=False)
    except ValueError:
        return

    cidr = '/' in ip_line
    total = ip.num_addresses if cidr else 1
    ip_info = {"source": source_name, "ip": str(ip), "lineNo": line_no, "duplicate": False, "cidr": cidr, "total": total}

    if ip.version == 4:
        result["ips"]["ipv4"].append(ip_info)
        result["meta"]["overall"]["totalIpv4"] += total
    elif ip.version == 6:
        result["ips"]["ipv6"].append(ip_info)
        result["meta"]["overall"]["totalIpv6"] += total

def process_file(file_path, source_name, result):
    """
    Process a file containing IP addresses and update the result.

    Args:
        file_path (str): The path to the file.
        source_name (str): The name of the data source.
        result (dict): The result dictionary to update.

    Returns:
        None
    """
    with open(file_path, 'r', encoding='latin-1') as file:
        lines = file.read().splitlines()

    for line_no, line in enumerate(lines, start=1):
        if line.strip():  # Skip empty lines
            process_ip_line(line, source_name, result, line_no)

def load_blacklist_directory(path):
    """
    Process a directory containing files and subdirectories with IP data.

    Args:
        path (str): The directory path to process.

    Returns:
        dict: The processed result containing IP information and metadata.
    """
    result = {"ips": {"ipv4": [], "ipv6": []}, "meta": {"overall": {"totalIpv4": 0, "totalIpv6": 0}, "sourceDetails": {}}}

    for root, _, files in os.walk(path):
        source_name = os.path.relpath(root, path)
        meta_data = load_meta_data(root)
        if meta_data:
            source_name = meta_data.get('name', source_name)
            source_info = result["meta"]["sourceDetails"].get(source_name, {})
            source_info.update(meta_data)
            result["meta"]["sourceDetails"][source_name] = source_info

        for filename in files:
            if filename != 'meta.json':
                file_path = os.path.join(root, filename)
                process_file(file_path, source_name, result)

    return result

def is_ip_blocked(ip_address, chain_name, ip_type="ipv4", protocol=None):
    """
    Check if an IP address is already blocked in an iptables or ip6tables chain.

    Args:
        ip_address (str): The IP address to check.
        chain_name (str): The name of the iptables or ip6tables chain.
        ip_type (str): Type of IP address, "ipv4" (default) or "ipv6".
        protocol (str): Optional protocol specification (e.g., "tcp", "udp").

    Returns:
        bool: True if the IP address is already blocked with the same protocol, False otherwise.
    """
    # Determine the appropriate command based on ip_type
    iptables_cmd = "iptables" if ip_type == "ipv4" else "ip6tables"

    # Check if the IP address is already blocked with the same protocol
    check_cmd = [iptables_cmd, "-C", chain_name, "-s", ip_address]
    if protocol:
        check_cmd += ["-p", protocol]
    else:
        check_cmd += ["-p", "all"]
    
    check_cmd += ["-j", "DROP"]

    try:
        subprocess.check_call(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError as e:
        if e.returncode != 0:
            return False

def block_ip(ip_address, chain_name, ip_type="ipv4", protocol=None):
    """
    Block an IP address in an iptables or ip6tables chain.

    Args:
        ip_address (str): The IP address to block.
        chain_name (str): The name of the iptables or ip6tables chain.
        ip_type (str): Type of IP address, "ipv4" (default) or "ipv6".
        protocol (str): Optional protocol specification (e.g., "tcp", "udp").

    Returns:
        None
    """
    # Check if the IP address is already blocked with the same protocol
    if is_ip_blocked(ip_address, chain_name, ip_type=ip_type, protocol=protocol):
        logging.info(f"IP address {ip_address} is already blocked.")
        return

    # Determine the appropriate command based on ip_type
    iptables_cmd = "iptables" if ip_type == "ipv4" else "ip6tables"

    # The chain may not exist, so we proceed to create it

    # Create the chain if it doesn't exist
    create_chain_cmd = [iptables_cmd, "-N", chain_name]
    subprocess.call(create_chain_cmd)

    # Add the IP address to the block list with an optional protocol specification
    block_cmd = [iptables_cmd, "-A", chain_name, "-s", ip_address]
    if protocol:
        block_cmd += ["-p", protocol]
    block_cmd += ["-j", "DROP"]

    try:
        subprocess.check_call(block_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logging.info(f"Blocked IP address {ip_address} in chain {chain_name} using {iptables_cmd}.")
    except subprocess.CalledProcessError as e:
        if e.returncode != 0:
            logging.error(f"Failed to block IP address {ip_address} in chain {chain_name} using {iptables_cmd}.")

# Create virtual environment
def create_virtualenv():
    """
    Create virtual environment.
    """
    # Directory path of file
    dir_path = os.path.dirname(os.path.realpath(__file__))

    if not os.path.isdir("venv"):
        subprocess.call(["python3", "-m", "venv", dir_path + "/venv"])
        # subprocess.call(["python3", "-m", "venv", "venv"])
        logging.info("Virtual environment created successfully.")
    else:
        logging.info("Virtual environment already exists.")

# Install dependencies
def install_dependencies():
    """
    Install dependencies.
    """

    dir_path = os.path.dirname(os.path.realpath(__file__))
    # subprocess.call([dir_path+"/venv/bin/python", "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.call([dir_path+"/venv/bin/python", "-m", "pip", "install", "-r", "requirements.txt"])
    
    logging.info("Dependencies installed successfully.")
