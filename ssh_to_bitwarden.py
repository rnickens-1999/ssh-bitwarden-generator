#!/usr/bin/env python3
"""
SSH Key to Bitwarden Generator
Scans for SSH keys and generates formatted content for Bitwarden secure notes.

GitHub: https://github.com/rnickens-1999/ssh-bitwarden-generator
Usage: curl https://raw.githubusercontent.com/rnickens-1999/ssh-bitwarden-generator/main/install.sh | bash
"""

import os
import glob
import subprocess
import json
import sys
import socket
import re
import platform
from datetime import datetime
from pathlib import Path

def get_interactive_input(prompt):
    """Get interactive input, handling cases where stdin might not be available."""
    try:
        # Try to read from /dev/tty first (works better in scripts)
        if os.path.exists('/dev/tty'):
            with open('/dev/tty', 'r') as tty:
                print(prompt, end='', flush=True)
                return tty.readline().strip()
        else:
            # Fallback to regular input
            return input(prompt).strip()
    except (EOFError, OSError):
        # If we can't get interactive input, return a default
        print(f"\nCannot read interactive input. Defaulting to processing all keys.")
        return 'all'

def get_generation_details():
    """Get comprehensive details about when and where the report was generated."""
    try:
        hostname = socket.gethostname()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        script_path = os.path.abspath(__file__)
        os_info = detect_operating_system()
        wsl_info = detect_wsl_environment()
        network_info = get_primary_mac_address()
        
        return hostname, timestamp, script_path, os_info, wsl_info, network_info
    except Exception:
        return "Unknown", "Unknown", "Unknown", "Unknown OS", None, "Unknown"

def detect_operating_system():
    """Detect operating system with detailed information including architecture."""
    try:
        system = platform.system()
        architecture = platform.machine()
        
        if system == "Linux":
            return detect_linux_details(architecture)
        elif system == "Windows":
            return detect_windows_details(architecture)
        elif system == "Darwin":
            return detect_macos_details(architecture)
        else:
            return f"{system} ({architecture})"
            
    except Exception:
        return "Unknown OS"

def detect_linux_details(architecture):
    """Detect detailed Linux distribution information."""
    try:
        # Try /etc/os-release first (most modern systems)
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                
            os_info = {}
            for line in lines:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    os_info[key] = value.strip('"')
            
            name = os_info.get('PRETTY_NAME', os_info.get('NAME', 'Linux'))
            return f"{name} ({architecture})"
            
        # Fallback to /etc/lsb-release
        elif os.path.exists('/etc/lsb-release'):
            with open('/etc/lsb-release', 'r') as f:
                content = f.read()
                
            if 'DISTRIB_DESCRIPTION' in content:
                for line in content.split('\n'):
                    if line.startswith('DISTRIB_DESCRIPTION='):
                        desc = line.split('=', 1)[1].strip('"')
                        return f"{desc} ({architecture})"
                        
        # Last resort - check for common distribution files
        distro_files = {
            '/etc/ubuntu-release': 'Ubuntu',
            '/etc/debian_version': 'Debian',
            '/etc/redhat-release': 'Red Hat',
            '/etc/centos-release': 'CentOS',
            '/etc/fedora-release': 'Fedora'
        }
        
        for file_path, distro_name in distro_files.items():
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        version = f.read().strip()
                    return f"{distro_name} {version} ({architecture})"
                except:
                    return f"{distro_name} ({architecture})"
                    
        return f"Linux ({architecture})"
        
    except Exception:
        return f"Linux ({architecture})"

def detect_windows_details(architecture):
    """Detect Windows version information."""
    try:
        release = platform.release()
        version = platform.version()
        
        # Try to get more detailed Windows version
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            product_name = winreg.QueryValueEx(key, "ProductName")[0]
            winreg.CloseKey(key)
            return f"{product_name} ({architecture})"
        except:
            pass
            
        return f"Windows {release} ({architecture})"
        
    except Exception:
        return f"Windows ({architecture})"

def detect_macos_details(architecture):
    """Detect macOS version information."""
    try:
        version, _, _ = platform.mac_ver()
        return f"macOS {version} ({architecture})"
    except Exception:
        return f"macOS ({architecture})"

def detect_wsl_environment():
    """Detect if running in WSL and get host Windows information."""
    try:
        # Check /proc/version for WSL indicators
        if os.path.exists('/proc/version'):
            with open('/proc/version', 'r') as f:
                proc_version = f.read().lower()
                
            if 'microsoft' in proc_version or 'wsl' in proc_version:
                # Determine WSL version
                wsl_version = "WSL2" if "wsl2" in proc_version else "WSL1"
                
                # Try to get Windows version from registry via WSL
                try:
                    # In WSL, we can access Windows registry
                    result = subprocess.run([
                        'powershell.exe', '-Command', 
                        '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").ProductName'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        windows_version = result.stdout.strip()
                        return f"{windows_version} ({wsl_version})"
                except:
                    pass
                    
                # Fallback to generic WSL detection
                return f"Windows ({wsl_version})"
                
    except Exception:
        pass
        
    return None

def get_network_interfaces():
    """Get available network interfaces using manual parsing."""
    interfaces = {}
    
    try:
        # Try to get interface list from /sys/class/net/
        if os.path.exists('/sys/class/net/'):
            for iface in os.listdir('/sys/class/net/'):
                if iface != 'lo':  # Skip loopback
                    interfaces[iface] = {'status': 'unknown', 'mac': None}
                    
                    # Check if interface is up
                    try:
                        operstate_file = f'/sys/class/net/{iface}/operstate'
                        if os.path.exists(operstate_file):
                            with open(operstate_file, 'r') as f:
                                status = f.read().strip()
                                interfaces[iface]['status'] = status
                    except:
                        pass
                        
                    # Get MAC address
                    try:
                        mac_file = f'/sys/class/net/{iface}/address'
                        if os.path.exists(mac_file):
                            with open(mac_file, 'r') as f:
                                mac = f.read().strip()
                                if mac and mac != '00:00:00:00:00:00':
                                    interfaces[iface]['mac'] = mac
                    except:
                        pass
        
        # Fallback: parse /proc/net/dev for interface names
        elif os.path.exists('/proc/net/dev'):
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
                
            for line in lines[2:]:  # Skip header lines
                if ':' in line:
                    iface = line.split(':')[0].strip()
                    if iface != 'lo':
                        interfaces[iface] = {'status': 'unknown', 'mac': None}
                        
    except Exception:
        pass
        
    return interfaces

def get_primary_mac_address():
    """Get MAC address with priority: Ethernet > WiFi > Other."""
    interfaces = get_network_interfaces()
    
    if not interfaces:
        return "Unknown"
    
    # Priority lists
    ethernet_patterns = ['eth', 'enp', 'eno', 'ens']
    wifi_patterns = ['wlan', 'wlp', 'wlo', 'wls']
    
    # Find active interfaces with MAC addresses
    active_interfaces = {}
    for iface, info in interfaces.items():
        if info['mac'] and info['status'] == 'up':
            active_interfaces[iface] = info
    
    # If no active interfaces, use any interface with MAC
    if not active_interfaces:
        active_interfaces = {k: v for k, v in interfaces.items() if v['mac']}
    
    if not active_interfaces:
        return "Unknown"
    
    # Priority 1: Ethernet interfaces
    for iface, info in active_interfaces.items():
        for pattern in ethernet_patterns:
            if iface.startswith(pattern):
                return f"Ethernet ({info['mac']})"
    
    # Priority 2: WiFi interfaces  
    for iface, info in active_interfaces.items():
        for pattern in wifi_patterns:
            if iface.startswith(pattern):
                return f"WiFi ({info['mac']})"
    
    # Priority 3: Any other interface
    first_iface = list(active_interfaces.keys())[0]
    mac = active_interfaces[first_iface]['mac']
    return f"Network ({mac})"

def detect_passphrase_required(private_key_path):
    """Detect if an SSH private key requires a passphrase."""
    try:
        with open(private_key_path, 'r') as f:
            content = f.read()
            
        # Check for OpenSSH format encryption
        if 'BEGIN OPENSSH PRIVATE KEY' in content:
            # Look for cipher information indicating encryption
            lines = content.split('\n')
            for line in lines[1:10]:  # Check first few lines after header
                if any(cipher in line for cipher in ['aes', 'des', 'cipher', 'kdf']):
                    return "Yes"
            # OpenSSH keys without encryption typically have "none" cipher
            if 'none' in content[:500]:  # Check early in file
                return "No"
            
        # Check for traditional PEM format encryption
        if any(marker in content for marker in [
            'Proc-Type: 4,ENCRYPTED',
            'DEK-Info:',
            'ENCRYPTED'
        ]):
            return "Yes"
            
        # If we can't determine, try to use ssh-keygen to check
        try:
            # Try to extract public key - if it succeeds without prompting, no passphrase
            result = subprocess.run(
                ['ssh-keygen', '-y', '-f', private_key_path], 
                capture_output=True, 
                text=True,
                timeout=2,
                input='\n'  # Send empty input
            )
            if result.returncode == 0:
                return "No"
            else:
                return "Yes"
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return "Yes"
            
    except Exception:
        pass
    
    return "Unknown"

def extract_email_from_public_key(private_key_path):
    """Extract email address from SSH public key comment."""
    public_key_path = private_key_path + '.pub'
    public_key_content = ""
    
    # First, try to read existing .pub file
    if os.path.exists(public_key_path):
        try:
            with open(public_key_path, 'r') as f:
                public_key_content = f.read().strip()
        except Exception:
            pass
    
    # If no .pub file or couldn't read it, try to extract from private key
    if not public_key_content:
        try:
            result = subprocess.run(
                ['ssh-keygen', '-y', '-f', private_key_path], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                public_key_content = result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    
    # Extract email from public key content
    if public_key_content:
        # Email is typically in the comment part (3rd field) of the public key
        parts = public_key_content.split()
        if len(parts) >= 3:
            comment = ' '.join(parts[2:])  # Everything after the key data
            
            # Look for email pattern in the comment
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            email_match = re.search(email_pattern, comment)
            if email_match:
                return email_match.group()
    
    return "Not found"

def get_key_info(private_key_path):
    """Extract information about an SSH key using ssh-keygen."""
    try:
        # Get key type and fingerprint
        result = subprocess.run(['ssh-keygen', '-lf', private_key_path], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            # Parse output: "2048 SHA256:fingerprint comment (RSA)"
            parts = result.stdout.strip().split()
            bit_length = parts[0]
            fingerprint = parts[1]
            key_type = parts[-1].strip('()')
            return bit_length, key_type, fingerprint
    except Exception as e:
        print(f"Warning: Could not get key info for {private_key_path}: {e}")
    return "Unknown", "Unknown", "Unknown"

def get_key_creation_date(private_key_path):
    """Get the creation date of the key file."""
    try:
        stat = os.stat(private_key_path)
        return datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d')
    except:
        return "Unknown"

def read_key_file(key_path):
    """Read and return the contents of a key file."""
    try:
        with open(key_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        return f"Error reading file: {e}"

def generate_bitwarden_entry(private_key_path):
    """Generate a formatted Bitwarden secure note entry for an SSH key."""
    
    # Get key information
    bit_length, key_type, fingerprint = get_key_info(private_key_path)
    creation_date = get_key_creation_date(private_key_path)
    
    # Get comprehensive generation details
    hostname, timestamp, script_path, os_info, wsl_info, network_info = get_generation_details()
    
    # Get enhanced key details
    requires_passphrase = detect_passphrase_required(private_key_path)
    associated_email = extract_email_from_public_key(private_key_path)
    
    # Read private key
    private_key_content = read_key_file(private_key_path)
    
    # Look for corresponding public key
    public_key_path = private_key_path + '.pub'
    public_key_content = ""
    if os.path.exists(public_key_path):
        public_key_content = read_key_file(public_key_path)
    else:
        # Try to generate public key from private key
        try:
            result = subprocess.run(['ssh-keygen', '-y', '-f', private_key_path], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                public_key_content = result.stdout.strip()
        except:
            public_key_content = "Could not generate public key"
    
    # Get key name (filename without path)
    key_name = os.path.basename(private_key_path)
    
    # Create enhanced title with hostname and OS info
    title = f"SSH Key - {key_name} - {hostname} - {os_info}"
    
    # Build generation details section
    gen_details = f"""--- Generation Details ---
Generated on: {hostname}
Generated at: {timestamp}
Operating System: {os_info}"""
    
    # Add WSL information if detected
    if wsl_info:
        gen_details += f"\nWSL Environment: {wsl_info}"
    
    # Add network interface information
    gen_details += f"\nNetwork Interface: {network_info}"
    gen_details += f"\nScript location: {script_path}"
    
    # Generate the formatted entry
    entry = f"""Title: {title}

Note Content:
Private Key:
{private_key_content}

Public Key:
{public_key_content}

{gen_details}

--- Key Details ---
Key Type: {key_type}
Bit Length: {bit_length}
Fingerprint: {fingerprint}
Creation Date: {creation_date}
Requires Passphrase: {requires_passphrase}
Associated Email: {associated_email}

--- Connection Details ---
Server/Service: [Enter server/service name]
Hostname/IP: [Enter hostname or IP address]
Port: 22
Username: [Enter username for this key]

--- Notes ---
[Add any additional notes about this key's usage]
Key File Location: {private_key_path}
"""
    
    return entry, key_name

def find_ssh_keys():
    """Find all SSH private keys in the ~/.ssh directory."""
    ssh_dir = os.path.expanduser('~/.ssh')
    if not os.path.exists(ssh_dir):
        print(f"SSH directory {ssh_dir} does not exist.")
        return []
    
    private_keys = []
    
    # Files to exclude from scanning
    excluded_files = {
        'known_hosts', 'known_hosts.old', 'authorized_keys', 'config', 
        'authorized_keys2', 'environment'
    }
    
    # Scan all files in the SSH directory
    try:
        for filename in os.listdir(ssh_dir):
            file_path = os.path.join(ssh_dir, filename)
            
            # Skip directories and excluded files
            if os.path.isdir(file_path):
                continue
                
            # Skip .pub files (public keys)
            if filename.endswith('.pub'):
                continue
                
            # Skip common SSH config files
            if filename in excluded_files:
                continue
                
            # Skip files that end with .old or .bak (backups)
            if filename.endswith(('.old', '.bak')):
                continue
            
            # Check if the file content looks like a private key
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                    
                    # Check for various SSH private key formats
                    if (('BEGIN' in first_line and 'PRIVATE KEY' in first_line) or
                        first_line.startswith('-----BEGIN OPENSSH PRIVATE KEY-----') or
                        first_line.startswith('-----BEGIN RSA PRIVATE KEY-----') or
                        first_line.startswith('-----BEGIN DSA PRIVATE KEY-----') or
                        first_line.startswith('-----BEGIN EC PRIVATE KEY-----') or
                        first_line.startswith('-----BEGIN ECDSA PRIVATE KEY-----') or
                        first_line.startswith('-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----')):
                        
                        private_keys.append(file_path)
                        
            except (UnicodeDecodeError, PermissionError, OSError):
                # Skip files that can't be read or are binary
                continue
                
    except PermissionError:
        print(f"Permission denied accessing {ssh_dir}")
        return []
    
    # Remove duplicates and sort
    private_keys = sorted(list(set(private_keys)))
    return private_keys

def main():
    print("SSH Key to Bitwarden Generator")
    print("=" * 40)
    
    # Find SSH keys
    ssh_keys = find_ssh_keys()
    
    if not ssh_keys:
        print("No SSH private keys found in ~/.ssh/")
        return
    
    print(f"Found {len(ssh_keys)} SSH key(s):")
    for i, key in enumerate(ssh_keys, 1):
        print(f"  {i}. {os.path.basename(key)}")
    
    print("\nSelect keys to process:")
    print("  - Enter numbers separated by commas (e.g., 1,3,4)")
    print("  - Enter 'all' to process all keys")
    print("  - Enter 'q' to quit")
    
    selection = get_interactive_input("\nYour choice: ").lower()
    
    if selection == 'q':
        return
    
    selected_keys = []
    if selection == 'all':
        selected_keys = ssh_keys
    else:
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected_keys = [ssh_keys[i] for i in indices if 0 <= i < len(ssh_keys)]
        except ValueError:
            print("Invalid selection. Exiting.")
            return
    
    # Process selected keys
    output_dir = os.path.expanduser('~/bitwarden_ssh_entries')
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\nProcessing {len(selected_keys)} key(s)...")
    print(f"Output will be saved to: {output_dir}")
    
    for key_path in selected_keys:
        try:
            entry_content, key_name = generate_bitwarden_entry(key_path)
            
            # Save to file
            output_file = os.path.join(output_dir, f"{key_name}_bitwarden.txt")
            with open(output_file, 'w') as f:
                f.write(entry_content)
            
            print(f"✓ Generated entry for {key_name} -> {output_file}")
            
        except Exception as e:
            print(f"✗ Error processing {key_path}: {e}")
    
    print(f"\nDone! Check the files in {output_dir}")
    print("Copy the content from these files into Bitwarden secure notes.")
    print("\nTip: You can also print a specific entry by running:")
    print(f"cat {output_dir}/[keyname]_bitwarden.txt")

if __name__ == "__main__":
    main()