"""Plaintext password checker against SecLists databases.

Searches for a password in SecLists to check if it's commonly known/leaked.

Author: Alex Wagner
"""
import os

def search_plaintext_password(password=None, verbose=False):
    """Search for a plaintext password in SecLists databases.

    Args:
        password: The plaintext password to search for (prompts if None)
        verbose: If True, print each file being checked

    Returns:
        List of file paths where the password was found
    """
    if password is None:
        password = input("🔑 Enter password to search for: ").strip()
        if not password:
            print("❌ No password entered.")
            return []

    home_dir = os.path.expanduser("~")
    seclists_path = os.path.join(home_dir, "SecLists", "Passwords")
    found_in = []

    if not os.path.isdir(seclists_path):
        print(f"❌ Directory not found: {seclists_path}")
        return found_in

    print(f"🔍 Searching for password in: {seclists_path}")

    for root, dirs, files in os.walk(seclists_path):
        for file in files:
            if file.endswith('.txt'):
                filepath = os.path.join(root, file)
                if verbose:
                    print(f"Checking: {filepath}")
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        if password in f.read().splitlines():
                            print(f"⚠️ Password found in: {filepath}")
                            found_in.append(filepath)
                except:
                    continue

    if not found_in:
        print("✅ Password not found in SecLists")

    return found_in


def main():
    print("=" * 60)
    print("  🔍 SecLists Password Checker")
    print("=" * 60)
    print()

    # Prompts user for password input
    found_in = search_plaintext_password()

    if found_in:
        print(f"\n📊 Found in {len(found_in)} file(s)")
        print("⚠️  This password is compromised and should not be used!")
    else:
        print("\n✅ Password appears to be unique (not in SecLists)")


if __name__ == "__main__":
    main()
