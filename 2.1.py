"""
Challenge 2.1 (Hard): Length Extension Attack

Extend the following message:
    "I give you the following amount of SEK coded in binary:\x12" #18 SEK.
    (The message is encoded in ASCII)

HMAC follows the insecure pattern h(key | msg), where the hash function is SHA-1.
- Key length: 7 bytes (Don't bruteforce it!)
- Original HMAC: 13ba7f327ebcd89929fec64a912e928ba627b1b0

Goal: Produce a message that extends the binary number in the original message,
      and generate a valid HMAC = h(key | extended_msg) without knowing the key.

Author: Alex Wagner.
Version: 1.5.
Date: 2025-11-26.
"""

import struct #Needed for packing data into binary format in continue_sha1.
import hashlib #Used in verify_attack function.

# Length Extension Attack on SHA-1 HMAC
# Goal: Extend the binary value \x12 (18 in decimal) withhout knowing the key

ORIGINAL_MESSAGE="I give you the following amount of SEK coded in binary:\x12"
ORIGINAL_HMAC = "13ba7f327ebcd89929fec64a912e928ba627b1b0"
KEY_LENGTH = 7 # Known key length in bytes.

#Helper function for continue_sha1
def _left_rotate(n, b):
    """Left-rotates a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

#Helper function for create_extended_message
def continue_sha1(h, data, total_length):
    """
    Continues SHA-1 hashing from a given internal state.

    Args:
        h: List of 5 SHA-1 state registers [h0, h1, h2, h3, h4]
        data: New data to append (bytes)
        total_length: Total length of the complete message (key + original + padding + new_data)

    Returns:
        str: Hex string of the new HMAC
    """
    # Calculate bit length for the ENTIRE message (key + original + padding + new_data)
    bit_length = total_length * 8

    # Add SHA-1 padding to new data only
    padded_data = data + b'\x80'

    # Pad with zeros until we're 8 bytes short of 64-byte boundary
    while (len(padded_data) + 8) % 64 != 0:
        padded_data += b'\x00'

    # Append TOTAL bit length (not just new data length)
    padded_data += bit_length.to_bytes(8, 'big')
    # Process in 64-byte chunks
    for i in range(0, len(padded_data), 64):
        chunk = padded_data[i:i+64]

        # Convert to 16 32-bit words
        w = list(struct.unpack('>16I', chunk))

        # Extend to 80 words
        for j in range(16, 80):
            w.append(_left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1))

        # Initialize working variables from current state
        a, b, c, d, e = h

        # 80 rounds of SHA-1
        for j in range(80):
            if j < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (_left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e, d, c, b, a = d, c, _left_rotate(b, 30), a, temp
        # Update state
        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff

    # Return final hash as hex string
    return ''.join(f'{x:08x}' for x in h)

#Extension strategy:
# SHA-1 processes data in 512-bit (64-byte) blocks with padding.
# Need to continue the hashing from the HMAC state by appending new data.

# Step 1: Calculate SHA-1 padding for (key + original_message)
def sha1_padding(message_length):
    """Generates SHA-1 padding for a message of a given length in bytes.

    SHA-1 padding: message + 0x80 + 0x00... + 64 bit length of the message."""
    #
    padding = b'\x80' #Step 1: Add mandatory 0x80 byte. This is one byte and 8 bits.
    original_bit_len = message_length * 8

    #Step 2: Add zero bytes until total length is divisible by 64 and gives 0 leftover.  (Sha is 64 bytes size).
    while (message_length + len(padding) + 8) % 64 != 0:
        padding += b'\x00'

    # Step 3: Append the original message length as a 64-bit big-endian integer
    padding += original_bit_len.to_bytes(8, byteorder='big') #to_bytes converts an integer to bytes.
    return padding

# Step 2: Implement the attack
def create_extended_message(data_to_append):
    """Performs a length extension attack on SHA-1 HMAC.

    Extends the original message without knowing the key by:
    1. Calculating padding for (key + original_message)
    2. Continuing SHA-1 hashing from the original HMAC state
    3. Appending new data and computing the extended HMAC
    """
    # Calculate total length of (key + original_message).
    total_length = KEY_LENGTH + len(ORIGINAL_MESSAGE)

    # Generate padding that was applied to the original message
    padding = sha1_padding(total_length)

    # Construct the extended message: original + padding + new data
    extended_message = ORIGINAL_MESSAGE.encode('latin-1') + padding + data_to_append.encode('latin-1')

    # TODO: Continue SHA-1 from the HMAC state and compute new hash.
    h = [int(ORIGINAL_HMAC[i:i+8], 16) for i in range(0, 40, 8)]

    # Calculate the forged message length for SHA-1 continuation
    forged_length = total_length + len(padding) + len(data_to_append.encode('latin-1'))

    # Continue SHA-1 hashing from the extracted state using the helper function continue_sha1.
    new_hmac = continue_sha1(h, data_to_append.encode('latin-1'), forged_length)

    return extended_message, new_hmac # Expected output: new_hmac and extended_message.

# Step 3: Test function: Verify the new HMAC is valid for (key + original_msg + padding + extension).
def verify_attack(extended_message_bytes, new_hmac, test_key=b"testkey"):
    """Verify the length extension attack by computing HMAC with a test key."""
    # Compute HMAC using the insecure h(key | msg) pattern.
    combined = test_key + extended_message_bytes
    actual_hmac = hashlib.sha1(combined).hexdigest()

    # For verification, we'd need to know if our forged HMAC matches
    # what the server would compute with the real key
    print(f"Test HMAC with test key: {actual_hmac}")
    print(f"Your forged HMAC: {new_hmac}")
    return actual_hmac == new_hmac
# Test function.
def display_message_content(extended_message_bytes):
    """Display the extended message in readable format."""
    print("=== MESSAGE CONTENT ANALYSIS ===\n")

    #    Original message part
    original_bytes = ORIGINAL_MESSAGE.encode('latin-1')
    print(f"1. Original Message:")
    print(f"   Bytes: {original_bytes}")
    print(f"   Text:  '{ORIGINAL_MESSAGE}'")
    print(f"   Hex:   {original_bytes.hex()}")

    # Find where padding starts (after original message)
    padding_start = len(original_bytes)

    # Find where extension starts (look for 0x34 at the end)
    extension_bytes = data_to_append.encode('latin-1')
    extension_start = len(extended_message_bytes) - len(extension_bytes)

    print(f"\n2. Padding Section:")
    padding_section = extended_message_bytes[padding_start:extension_start]
    print(f"   Length: {len(padding_section)} bytes")
    print(f"   Hex:    {padding_section.hex()}")

    print(f"\n3. Extension (New Data):")
    print(f"   Bytes: {extension_bytes}")
    print(f"   Text:  '{data_to_append}' (this is \\x34)")
    print(f"   Hex:   {extension_bytes.hex()}")

    print(f"\n4. Binary Value Analysis:")
    original_value = ord('\x12')  # Convert \x12 to decimal
    extension_value = ord('\x34')  # Convert \x34 to decimal
    print(f"   Original \\x12 = {original_value} decimal = {bin(original_value)} binary")
    print(f"   Extension \\x34 = {extension_value} decimal = {bin(extension_value)} binary")

    print(f"\n5. Complete Extended Message:")
    print(f"   Total length: {len(extended_message_bytes)} bytes")
    print(f"   Full hex: {extended_message_bytes.hex()}")

# Main method.
if __name__ == "__main__":
    # Prompt user for the data to append the message with.
    data_to_append = input("Enter the data to append (e.g., \\x0a for 10, or just 5): ")
    data_to_append = data_to_append.encode('latin-1').decode('unicode_escape')

    extended_message, new_hmac = create_extended_message(data_to_append)
    print(f"New HMAC: {new_hmac}")
    print(f"Extended Message (hex): {extended_message.hex()}")

    # Verify that the structure is correct.
    print(f"\nMessage Analysis:")
    print(f"Original ends with: {ORIGINAL_MESSAGE.encode('latin-1').hex()}")
    print(f"Extension starts with: {data_to_append.encode('latin-1').hex()}")

    # Test function: Display readable content
    # display_message_content(extended_message)



