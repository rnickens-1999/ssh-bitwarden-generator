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
from datetime import datetime
from pathlib import Path

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
                                  capture_output=True, text=True)
            if result.returncode == 0:
                public_key_content = result.stdout.strip()
        except:
            public_key_content = "Could not generate public key"
    
    # Get key name (filename without path)
    key_name = os.path.basename(private_key_path)
    
    # Generate the formatted entry
    entry = f"""Title: SSH Key - {key_name}

Note Content:
Private Key:
{private_key_content}

Public Key:
{public_key_content}

--- Key Details ---
Key Type: {key_type}
Bit Length: {bit_length}
Fingerprint: {fingerprint}
Creation Date: {creation_date}
Passphrase: [Enter passphrase if key is encrypted]

--- Connection Details ---
Server/Service: [Enter server/service name]
Hostname/IP: [Enter hostname or IP address]
Port: 22
Username: [Enter username for this key]
Associated Email: [Enter associated email]

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
    
    # Look for common SSH key patterns
    key_patterns = [
        os.path.join(ssh_dir, 'id_*'),
        os.path.join(ssh_dir, '*_rsa'),
        os.path.join(ssh_dir, '*_ed25519'),
        os.path.join(ssh_dir, '*_ecdsa'),
    ]
    
    private_keys = []
    for pattern in key_patterns:
        for key_file in glob.glob(pattern):
            # Skip .pub files and known_hosts, authorized_keys, etc.
            if (not key_file.endswith('.pub') and 
                not key_file.endswith('known_hosts') and
                not key_file.endswith('authorized_keys') and
                not key_file.endswith('config')):
                
                # Check if it looks like a private key
                try:
                    with open(key_file, 'r') as f:
                        first_line = f.readline()
                        if ('BEGIN' in first_line and 'PRIVATE KEY' in first_line) or \
                           first_line.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
                            private_keys.append(key_file)
                except:
                    pass
    
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
    
    selection = input("\nYour choice: ").strip().lower()
    
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