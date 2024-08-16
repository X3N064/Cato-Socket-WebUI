import subprocess
import datetime
import re
import sys
import os
import ctypes

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def validate_ip(ip):
    """Validate the format of an IP address."""
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return pattern.match(ip)

def find_interface_name():
    """Find the network interface to configure."""
    command = 'netsh interface show interface'
    result = subprocess.run(command, capture_output=True, text=True, shell=True)

    interfaces = result.stdout
    if "Ethernet" in interfaces:
        return "Ethernet"
    elif "이더넷" in interfaces:
        return "이더넷"
    else:
        print("Neither 'Ethernet' nor '이더넷' found. Please check your network interfaces.")
        sys.exit(1)

def find_interface_guid(interface):
    """Find the GUID of the specified network interface."""
    command = f'powershell -Command "(Get-NetAdapter -Name \'{interface}\').InterfaceGuid"'
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    guid = result.stdout.strip()

    if guid:
        return guid
    else:
        print(f"Could not find the GUID for the interface '{interface}'.")
        sys.exit(1)

import subprocess

def set_ip_address(interface, ip_address, subnet_mask, gateway):
    """Set a static IP address on the specified interface."""
    if not (validate_ip(ip_address) and validate_ip(subnet_mask) and validate_ip(gateway)):
        print("Invalid IP address, subnet mask, or gateway format.")
        subprocess.run("pause", check=True, shell=True)
        return

    interface_guid = find_interface_guid(interface)
    
    command1 = f'netsh interface ipv4 set address name="{interface}" static {ip_address} {subnet_mask} {gateway}'
    command2 = f'netsh interface ipv4 set dns name="{interface}" static 8.8.8.8'
    command3 = f'powershell -Command "Set-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{interface_guid}\' -Name EnableDHCP -Value 0"'

    try:
        subprocess.run(command1, check=True, shell=True)
        subprocess.run(command2, check=True, shell=True)
        subprocess.run(command3, check=True, shell=True)
        print(f"IP address({ip_address}), subnet mask({subnet_mask}), and default gateway({gateway}) set on interface {interface}")
        print_ifconfig(interface)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        subprocess.run("pause", check=True, shell=True)


def enable_dhcp(interface):
    """Enable DHCP on the specified interface."""
    command = f'netsh interface ip set address name="{interface}" source=dhcp'
    command1 = f'netsh interface ip set dns name="{interface}" source=dhcp'

    
    try:
        subprocess.run(command, check=True, shell=True)
        subprocess.run(command1, check=True, shell=True)
        print(f"DHCP enabled on interface {interface}")
        print_ifconfig(interface)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        print("\n\nDon't worry even if error happened. It worked properly.\n")
        subprocess.run("pause", check=True, shell=True)

def print_ifconfig(interface):
    """Display the current IP configuration of the specified interface."""
    interface_guid = find_interface_guid(interface)
    
    check_command = f'powershell -Command "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{interface_guid}\' -Name EnableDHCP"'
    result = subprocess.run(check_command, capture_output=True, text=True, shell=True)
    output_lines = result.stdout.splitlines()
    enable_dhcp_value = 0
    
    for line in output_lines:
        if "EnableDHCP" in line:
            # Extract the value after the colon and strip any whitespace
            enable_dhcp_value = line.split(":")[1].strip()
            print(f"EnableDHCP: {enable_dhcp_value}")
        
    print("interface = ", interface, "guid = ", interface_guid)
    
    if enable_dhcp_value == '1':
        print("DHCP is enabled.")
        subprocess.run("pause", check=True, shell=True)
    else:
        command = f'powershell -Command Get-NetIPAddress -InterfaceAlias "{interface}" -PrefixOrigin Manual'
        command1 = f'netsh interface ipv4 show config name="{interface}"'
        
        try:
            subprocess.run(command, check=True, shell=True)
            subprocess.run(command1, check=True, shell=True)
            print()
            subprocess.run("pause", check=True, shell=True)
        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e.stderr}")
            subprocess.run("pause", check=True, shell=True)

def backup_config(interface):
    """Backup the current IP configuration of the specified interface."""
    ip_command = f'powershell -Command Get-NetIPAddress -InterfaceAlias "{interface}"'
    ip_result = subprocess.run(ip_command, capture_output=True, text=True, shell=True)
    
    command = f'netsh interface ipv4 show config name="{interface}"'
    result = subprocess.run(command, capture_output=True, text=True, shell=True)

    
    combined_output = ip_result.stdout + "\n" + result.stdout
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"backup_{timestamp}.txt"
    
    with open(file_name, "w") as file:
        file.write(combined_output)
        
    print(f"Backup saved to {file_name}")

if __name__ == "__main__":
    # Check if the script is running with admin privileges
    if not is_admin():
        print("\nThis program needs to be run with administrative privileges.\n")
        input("Press Enter to exit and then re-run the program as an administrator.")
        sys.exit(0)

    # If running as admin, continue with the main functionality
    while True:
        choice = input("Choose \n 1 = to set IP for accessing Socket WebUI \n 2 = to rollback to DHCP \n 3 = to show current config \n 4 = to exit \n:").strip().lower()
        
        if choice == "4":
            print("Exiting the program.")
            sys.exit(0)
        
        if choice not in ["1", "2", "3"]:
            print("Invalid choice. Please enter a valid option.")
            subprocess.run("pause", check=True, shell=True)
            os.system("cls")
            continue

        interface = find_interface_name()
        interface_guid = find_interface_guid(interface)  # Moved this after finding the interface
        ip_address = "169.254.100.100"
        subnet_mask = "255.255.0.0"
        gateway = "169.254.100.1"

        if choice == "1":
            backup_config(interface)  # Backup before changing
            set_ip_address(interface, ip_address, subnet_mask, gateway)
        elif choice == "2":
            backup_config(interface)  # Backup before changing
            enable_dhcp(interface)
        elif choice == "3":
            print_ifconfig(interface)

        # Clear the screen after each operation
        os.system("cls")  # Use "clear" for macOS/Linux
