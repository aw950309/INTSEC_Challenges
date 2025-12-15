"""Challenge 3.2 (Normal): Break weak passwords with salt h(password || Salt)

Question format:  Hash-Algo, Hash, Salt, Hint

1. SHA1, d2e5d1914bc54bc0f8327077ed8219010c607410, 1cb6, PIN code

2. SSHA-256, 8024675872cf97e4ec8d608f379e9bd8035a5f21fe6f80e241169a81a561dfaf, fe66, L1tera11y a password

3. md5, d249bf47a16435ed04f3c2d52ea29459, c036, Under your nose

Author: Alex Wagner.
Version: 1.0.
Date: 2025-12-12.
"""
import hashlib
import itertools
import utils

SHA1_HASH = "d2e5d1914bc54bc0f8327077ed8219010c607410"
SHA1_SALT = "1cb6"

SHA256_HASH = "8024675872cf97e4ec8d608f379e9bd8035a5f21fe6f80e241169a81a561dfaf"
SHA256_SALT = "fe66"

MD5_HASH = "d249bf47a16435ed04f3c2d52ea29459"
MD5_SALT = "c036"

def crack_sha1_pin_code_with_salt(target_hash, salt, verbose=False):
    """Brute-force a 4-digit PIN code hashed with SHA1 and salt."""
    return utils.crack_pin_code(target_hash, salt=salt, verbose = verbose)  # Passes salt parameter

def crack_md5_with_salt(target_hash, salt, verbose=False):
    """Crack MD5 hash with salt using SecLists."""
    return utils.crack_from_seclists(target_hash, 'md5', salt=salt, verbose=verbose)

def crack_sha256_with_salt(target_hash, salt, verbose=False):
    """Crack SHA-256 hash with salt using SecLists."""
    return utils.crack_from_seclists(target_hash, 'sha256', salt=salt, verbose=verbose)

def main():
    verbose = utils.get_verbose_preference()

    utils.print_section_header("🔐 Cracking SHA1 PIN Code")
    sha1_pin = crack_sha1_pin_code_with_salt(SHA1_HASH, SHA1_SALT, verbose)
    if sha1_pin:
        print(f"✅ Cracked SHA1 PIN code with salt: {sha1_pin}")
    else:
        print("❌ Failed to crack SHA1 PIN code.")

    utils.print_section_header("🔐 Cracking SHA-256 Password")
    sha256_password = crack_sha256_with_salt(SHA256_HASH, SHA256_SALT, verbose)
    if sha256_password:
        print(f"✅ Cracked SHA-256 password with salt: {sha256_password}")
    else:
        print("❌ Failed to crack SHA-256 password.")

    utils.print_section_header("🔐 Cracking MD5 Password")
    md5_password = crack_md5_with_salt(MD5_HASH, MD5_SALT, verbose)
    if md5_password:
        print(f"✅ Cracked MD5 password with salt: {md5_password}")
    else:
        print("❌ Failed to crack MD5 password.")

    print(f"{'='*60}")



if __name__ == "__main__":
    main()
