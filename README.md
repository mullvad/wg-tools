# wg-mullvad.py

This repository contains a python script that generates WireGuard®[^1] configuration files for all Mullvad relays.

The script can generate, save and reuse a private key when generating configurations.

## User guide:
There are some builtin functions to help the user: To see all options use **--help**.

### Settings file
If the **--settings-file** does not exist it will be created, and a private key for WireGuard will be generated.
Everytime the program is executed, it will login to the account and check that the device exists. If not it will try to create it. Any file in ini format that contains a "privatekey"-entry is a valid settings file. Even an existing configuration file can be used as a settings file as long as it contains the private key.

### Filter
**--filter** is an option to limit the number of files that will be edited or created. The filter search will match any hostname that contains the given term. **--filter se-got** would generate files for all relays in Gothenburg Sweden. Standard name scheme for relays are: **\<country-city-type-identifier>**.

### Multihop
**--multihop-server** has a built in search. If the specified term does not respond to exactly 1 server, it will show the servers matching the search term. Example: **--multihop-server se-got** will show all the possible multihop-servers in Gothenburg Sweden. **--multihop-server se-got-wg-001** would set this server as multihop server in all configurations.

### Files and Folders
Files will only be edited or added, never removed. If you want to start over, just remove the folder with configuration files created, e.g. **(~/.config/mullvad/wg0)**. Its also possible to run the program many times to add different setups.

## Examples

    # Create WireGuard files for all relays in Gothenburg:
    ./wg-mullvad.py --account <myaccountnumber> --filter se-got
    
    # Create files for all relays in Stockholm
    ./wg-mullvad.py --account <myaccountnumber> --filter se-sto
    
    # Create files for all servers via se-got-wg-001
    ./wg-mullvad.py --account <myaccountnumber> --multihop-server se-got-wg-001
    
    # Create multihop files for servers in Stockholm via se-got-wg-003
    ./wg-mullvad.py --account <myaccountnumber> --multihop-server se-got-wg-003 --filter se-sto
    
## Multihop options
 There are 3 different ways to do multihop with mullvad.
 
 1. Multihop by using special port in WireGuard config (described above).
 2. Using [Socks](https://mullvad.net/en/help/different-entryexit-node-using-wireguard-and-socks5-proxy).
 3. Using a WireGuard tunnel in a WireGuard tunnel (requires more complex routing setup and outside the scope of this guide).

[^1]: "WireGuard" is a registered trademark of Jason A. Donenfeld.