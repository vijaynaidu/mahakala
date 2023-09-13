# Mahakala
Nerd's firewall for server hardening. Block the ip's from the data sources and add them to the iptables block list.

## Setting up & Configuring firewall
1. Clone the repository `git@github.com:vijaynaidu/mahakala.git`
2. Fetch the ips from the data sources and add them to the `data/ip-blacklist/{source}/{file-name}.txt` file.
3. Fetch the ips from some known sources using command `python3 fetch_blacklist_ips.py`. This will fetch the ips from the sources and add them to the `data/ip-blacklist/{source}/{file-name}.txt` file.
4. Navigate to the project directory and initiate python script to add the ips into block list of iptables. `python3 main.py`
5. Check if the ip's in the block list are added to the iptables using command `iptables -L -n --line-numbers` and `ip6tables -L -n --line-numbers`


## Data Sources
- [https://github.com/SilvrrGIT/IP-Lists/tree/master](https://github.com/SilvrrGIT/IP-Lists/tree/master)
- [https://wiki.ipfire.org/configuration/firewall/blockshodan](https://wiki.ipfire.org/configuration/firewall/blockshodan)
- [https://github.com/stamparm/ipsum/tree/master](https://github.com/stamparm/ipsum/tree/master)


## Quick Commands
- `iptables -n -L MAHAKALA_BLACKLIST_INPUT --line-numbers` and `ip6tables -n -L MAHAKALA_BLACKLIST_INPUT --line-numbers` - List all the rules in the iptables of chain MAHAKALA_BLACKLIST_INPUT
- `iptables -L -n --line-numbers` - List all the rules in the iptables
- `iptables -D INPUT <rule number>` - Delete a rule from iptables
