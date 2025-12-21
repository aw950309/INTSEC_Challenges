"""Shared utility functions for password cracking challenges. Used for both 3.1 and 3.2."""
import hashlib
import itertools
import os

def crack_from_seclists(target_hash, hash_algorithm, salt="", verbose=False):
    """Generic cracking function using SecLists common credential files.
 #Helper method used in crack_sha256_common_password and crack_md5_weak_password functions.
 salt is an optional variable and defaults to empty string.
 Verbose False is the default but overwritten by the helper methods.

 Args:
     target_hash: The hash to crack
     hash_algorithm: Hash algorithm name (e.g., 'md5', 'sha1', 'sha256')
     salt: Optional salt to append to password (default: empty string)
     verbose: Whether to print progress information (default: False)
 """
    home_dir = os.path.expanduser("~")
    passwords_base = os.path.join(home_dir, "SecLists", "Passwords")

    if not os.path.isdir(passwords_base):
        if verbose:
            print(f"Passwords directory not found at: {passwords_base}")
        return None

    hash_func = getattr(hashlib, hash_algorithm)

    # PRIORITY: Check Common-Credentials first (I got myself a bug where it gave up before even getting to this one lol)
    common_creds_dir = os.path.join(passwords_base, "Common-Credentials")
    if os.path.isdir(common_creds_dir):
        if verbose:
            print(f"[*] Checking Common-Credentials first...")
        result = _search_in_directory(common_creds_dir, target_hash, hash_func, salt, verbose)
        if result:
            return result

    # Then search all other directories recursively.
    if verbose:
        print(f"[*] Searching all other password directories...")
    for root, dirs, files in os.walk(passwords_base):
        # Skip Common-Credentials since we already checked it
        if root == common_creds_dir:
            continue

        result = _search_in_directory(root, target_hash, hash_func, salt, verbose)
        if result:
            return result

    return None

def _search_in_directory(directory, target_hash, hash_func, salt, verbose):
    """Helper function to search all .txt files in a directory."""
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            file_path = os.path.join(directory, filename)
            if verbose:
                print(f"[*] Checking: {filename}")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        pwd = line.strip()
                        if not pwd:
                            continue

                        # Try password+salt
                        if hash_func((pwd + salt).encode()).hexdigest() == target_hash:
                            if verbose:
                                print(f"\n[+] Found in {filename} (password+salt order)!")
                            return pwd

                        # Try salt+password
                        if hash_func((salt + pwd).encode()).hexdigest() == target_hash:
                            if verbose:
                                print(f"\n[+] Found in {filename} (salt+password order)!")
                            return pwd
            except Exception as e:
                if verbose:
                    print(f"Could not read {filename}: {e}")
    return None

def crack_pin_code(target_hash, hash_algorithm='sha1', salt="", verbose=False):
    """Brute-force a 4-digit PIN code with optional salt.

    Args:
        target_hash: The hash to crack
        hash_algorithm: Hash algorithm name (default: 'sha1')
        salt: Optional salt to append to PIN (default: empty string)
    """
    hash_func = getattr(hashlib, hash_algorithm)

    for pin in itertools.product('0123456789', repeat=4):
        pin_str = ''.join(pin)
        # Concatenate PIN with salt before hashing
        hashed_pin = hash_func((pin_str + salt).encode()).hexdigest()
        if hashed_pin == target_hash:
            return pin_str
    return None

def get_verbose_preference():
    """Ask user if they want verbose output and return boolean."""
    verbose_input = input("Do you want verbose output? (Y/n): ").strip().lower()
    verbose = verbose_input != 'n'  # Default to True unless user types 'n'

    print(f"\n{'='*50}")
    print(f"Running with verbose={'ON' if verbose else 'OFF'}")
    print(f"{'='*50}\n")

    return verbose

def print_section_header(message):
    """Print a visually distinct section header."""
    print(f"{'='*60}")
    print(f"  {message}")
    print(f"{'='*60}")

def get_common_passwords(verbose=False):
    """Get list of common passwords from SecLists for brute-force attacks.

    Returns:
        list: List of password strings from Common-Credentials directory
    """
    home_dir = os.path.expanduser("~")
    passwords_base = os.path.join(home_dir, "SecLists", "Passwords", "Common-Credentials")

    if not os.path.isdir(passwords_base):
        if verbose:
            print(f"Passwords directory not found at: {passwords_base}")
        return []

    passwords = []
    for filename in os.listdir(passwords_base):
        if filename.endswith('.txt'):
            filepath = os.path.join(passwords_base, filename)
            try:
                with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                    for line in f:
                        pwd = line.strip()
                        if pwd and not pwd.startswith('#'):
                            passwords.append(pwd)
            except Exception as e:
                if verbose:
                    print(f"Could not read {filename}: {e}")

    return passwords