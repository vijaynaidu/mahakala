"""
Main module for Mahakala Firewall.
"""
import logging
import os

from methods import check_virtualenv, check_root, check_iptables, check_ip6tables, load_blacklist_directory, block_ip, create_virtualenv, install_dependencies, chain_exists, create_chain

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    if not check_root():
        logging.error("Please run as root. Require sudo.")
        exit(1)
    
    if not check_iptables() or not check_ip6tables():
        logging.error("iptables | ip6tables not found. Please install iptables.")
        exit(1)

    if not check_virtualenv():
        create_virtualenv()
        install_dependencies()
    
    logging.info("Block IP's from the blacklist.")

    dir_path = os.path.dirname(os.path.realpath(__file__))
    blacklist = load_blacklist_directory(dir_path+"/data/ip-blacklist")

    # Define the chain name and IP type (ipv4 or ipv6)
    chain_name = "MAHAKALA-BLACKLIST"

    # Iterate through IPv4 addresses
    for ipv4_info in blacklist["ips"]["ipv4"]:
        if not chain_exists(chain_name, "ipv4"):
            create_chain(chain_name=chain_name, policy="DROP", ip_type="ipv4")
        ip_address = ipv4_info["ip"]
        block_ip(ip_address, chain_name, ip_type="ipv4")

    # Iterate through IPv6 addresses
    for ipv6_info in blacklist["ips"]["ipv6"]:
        if not chain_exists(chain_name, "ipv6"):
            create_chain(chain_name=chain_name, policy="DROP", ip_type="ipv6")
        ip_address = ipv6_info["ip"]
        block_ip(ip_address, chain_name, ip_type="ipv6")


# iptables -F && ip6tables -F
# iptables -n -L MAHAKALA-BLACKLIST --line-numbers
# ip6tables -n -L MAHAKALA-BLACKLIST --line-numbers
