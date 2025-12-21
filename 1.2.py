"""
Decrypts an XOR-encrypted file using a known plaintext attack combined with a targeted brute-force.

Technical details:
    - Key length: 120 bits (15 bytes).
    - Encryption method: Repeating-key XOR.
    - Attack: Known-plaintext for the first 14 bytes, brute-force for the last byte.
    - Time complexity: O(n).

Prerequisites:
    - The file "Challenge-1.2.enc" must be in the same directory as this script.
    - Python 3.x required.

Author: Alex Wagner.
Version: 2.1.
Date: 2025-11-13.
"""

def read_encrypted_file(filepath):
    """Reads the binary content of the encrypted file."""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: '{filepath}' not found.")
        return None

def decrypt_with_key(ciphertext_bytes, key):
    """Decrypts the ciphertext using a given repeating key."""
    key_length = len(key)
    decrypted_bytes = bytearray(len(ciphertext_bytes))
    for i in range(len(ciphertext_bytes)):
        decrypted_bytes[i] = ciphertext_bytes[i] ^ key[i % key_length]
    return decrypted_bytes

def recover_partial_key(ciphertext_bytes, known_plaintext_bytes, key_length):
    """Recovers the initial part of the key using known plaintext."""
    partial_key = bytearray(key_length)
    for i in range(len(known_plaintext_bytes)):
        partial_key[i] = ciphertext_bytes[i] ^ known_plaintext_bytes[i]
    return partial_key

def find_key_and_decrypt(ciphertext_bytes, partial_key, validation_string):
    """
    Brute-forces the last byte of the key and validates the decryption.
    Returns the full key and decrypted text if successful, otherwise None.
    """
    key_length = len(partial_key)
    for last_byte in range(256):
        candidate_key = partial_key.copy()
        candidate_key[key_length - 1] = last_byte

        decrypted_bytes = decrypt_with_key(ciphertext_bytes, candidate_key)
        try:
            decrypted_text = decrypted_bytes.decode('ascii')
            if validation_string in decrypted_text[:50]:
                return candidate_key, decrypted_text  # Return tuple on success
        except UnicodeDecodeError:
            continue
    return None, None  # Return tuple on failure

def main():
    """
    Decrypts the Challenge-1.2.enc file by coordinating helper functions.
    """
    # --- Configuration ---
    filepath = 'Challenge-1.2.enc'
    key_length = 15
    known_plaintext = "Challenge 1.2\n"
    validation_string = "simple file"
    # ---

    # Step 1: Read the encrypted file.
    ciphertext_bytes = read_encrypted_file(filepath)
    if not ciphertext_bytes:
        return

    # Step 2: Recover the first 14 bytes of the key using the known plaintext.
    # This works because: Plaintext XOR Ciphertext = Key.
    known_plaintext_bytes = known_plaintext.encode('ascii')
    partial_key = recover_partial_key(ciphertext_bytes, known_plaintext_bytes, key_length)

    # Step 3: Brute-force the final key byte to find the full key and message.
    # It tries every possible value (0-255) for the last byte and checks if the
    # resulting decryption contains the validation string.
    final_key, decrypted_text = find_key_and_decrypt(ciphertext_bytes, partial_key, validation_string)

    # Step 4: Print the results to the console.
    if final_key and decrypted_text:
        print("Success! Key recovered.")
        print(f"Key (hex): {final_key.hex()}")
        print(f"\nDecrypted message:\n{decrypted_text}")
    else:
        print("Failed to find the key. The known plaintext or validation word might be incorrect.")

# Main method.
if __name__ == "__main__":
    main()