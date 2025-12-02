"""Authentication

Challenge 3.1 (Normal): Break weak passwords (with no salt)

They follow the format: Hash-Algo, Hash, Hint

SHA1, e892cd3809fc776264670f4e7f3c9a48a6516f21, PIN code

md5, 24eb05d18318ac2db8b2b959315d10f2, weak

SHA-256, 8e700dced16a90556f13c734b3dc9f8fa9b273a2a263d669c3efe69eeb156c2f, common

Author: Alex Wagner.
Version: 1.2.
Date: 2025-11-28.
"""

import hashlib
import itertools
import os

SHA1_HASH = "e892cd3809fc776264670f4e7f3c9a48a6516f21"
MD5_HASH = "24eb05d18318ac2db8b2b959315d10f2"
SHA_256_HASH = "8e700dced16a90556f13c734b3dc9f8fa9b273a2a263d669c3efe69eeb156c2f"

def crack_from_seclists(target_hash, hash_algorithm, verbose=False): #Helper method used in crack_sha256_common_password and crack_md5_weak_password functions. Verbose False is the default but overwritten by the helper methods.
    """Generic cracking function using SecLists common credential files."""
    home_dir = os.path.expanduser("~")
    passwords_dir = os.path.join(home_dir, "SecLists", "Passwords", "Common-Credentials")

    if not os.path.isdir(passwords_dir):
        if verbose:
            print(f"Passwords directory not found at: {passwords_dir}")
            print("Please ensure SecLists is cloned in your home directory or adjust the path.")
        return None

    hash_func = getattr(hashlib, hash_algorithm)

    for filename in os.listdir(passwords_dir):
        if filename.endswith(".txt"):
            file_path = os.path.join(passwords_dir, filename)
            if verbose:
                print(f"[*] Checking passwords in: {filename}")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        pwd = line.strip()
                        if not pwd:
                            continue
                        hashed_pwd = hash_func(pwd.encode()).hexdigest()
                        if hashed_pwd == target_hash:
                            if verbose:
                                print(f"\n[+] Found password in {filename}!")
                            return pwd
            except Exception as e:
                if verbose:
                    print(f"Could not read file {filename}: {e}")
    return None

def crack_sha1_pin_code(target_hash):
    """Brute-force a 4-digit PIN code hashed with SHA1."""
    for pin in itertools.product('0123456789', repeat=4):
        pin_str = ''.join(pin)
        hashed_pin = hashlib.sha1(pin_str.encode()).hexdigest()
        if hashed_pin == target_hash:
            return pin_str
    return None

def crack_md5_weak_password(target_hash):
    """Crack  by checking common password lists from the SecLists repository."""
    return crack_from_seclists(target_hash, 'md5', verbose=True) #Verbose=true argument controls whether a funtion prints detailed progress information while it runs.

def crack_sha256_common_password(target_hash):
    """Crack by checking common password lists from the SecLists repository."""
    return crack_from_seclists(target_hash, 'sha256', verbose=True) #Verbose=true argument controls whether a funtion prints detailed progress information while it runs.

def main():
    sha1_pin = crack_sha1_pin_code(SHA1_HASH)
    if sha1_pin:
        print(f"Cracked SHA1 PIN code: {sha1_pin}")
    else:
        print("Failed to crack SHA1 PIN code.")

    md5_password = crack_md5_weak_password(MD5_HASH)
    if md5_password:
        print(f"Cracked MD5 weak password: {md5_password}")
    else:
        print("Failed to crack MD5 weak password.")

    sha256_password = crack_sha256_common_password(SHA_256_HASH)
    if sha256_password:
        print(f"Cracked SHA-256 common password: {sha256_password}")
    else:
        print("Failed to crack SHA-256 common password.")

if __name__ == "__main__":
    main()
