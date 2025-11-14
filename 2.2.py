"""
Verifies the integrity of messages using a custom nested HMAC-SHA1 algorithm.

This script defines a set of messages, each with a corresponding HMAC.
It then iterates through each message, recalculates the HMAC using two secret
keys, and compares the result to the provided HMAC to check for tampering.

The custom HMAC algorithm is defined as: HMAC = SHA1(KEY_2 + SHA1(KEY_1 + MESSAGE))
"""

import hashlib

KEY_1 = "1234"
KEY_2 = "5678"

MESSAGES_TO_VERIFY = [
    {"text": "Challenge 2.2 is easy.", "hmac": "12d44a1c2448cc54ddffc75e69313a7964d5d775"},
    {"text": "Challenge 2.2 is doable.", "hmac": "1b25d0e281f73935f7a122c088c1bc34686b271b"},
    {"text": "Challenge 2.2 is hard.", "hmac": "aec64e480f251c6811686597305b04edcc25da35"}
]

def verify_hmac(message, provided_hmac, KEY_1, KEY_2):
    """
   Calculates and verifies a custom nested HMAC-SHA1.

   This function implements the h(key_2 | h(key_1 | msg)) algorithm.
   The verification process follows these steps:

   1. Compute an inner hash: SHA1(KEY_1 + MESSAGE).
   2. Compute an outer hash using the inner hash: SHA1(KEY_2 + inner_hash).
   3. Compare the final calculated HMAC with the provided HMAC.

   @param message (str): The message text to verify.
   @param provided_hmac (str): The hex-encoded HMAC to check against.
   @param KEY_1 (str): The secret key for the inner hash.
   @param KEY_2 (str): The secret key for the outer hash.
   @return (bool): True if the calculated HMAC matches the provided HMAC, False otherwise.
   """

    # Step 1: Calculate the inner hash: h(key_1 | msg).
    inner_data = KEY_1.encode('ascii') + message.encode('ascii')
    inner_hash = hashlib.sha1(inner_data).hexdigest()

    # Step 2: Calculate the outer hash: h(key_2 | inner_hash).
    # The inner hash is used as an ASCII string for the outer hash calculation.
    outer_data = KEY_2.encode('ascii') + inner_hash.encode('ascii')
    calculated_hmac = hashlib.sha1(outer_data).hexdigest()

    # Step 3: Compare the calculated HMAC with the provided one.
    return calculated_hmac == provided_hmac


def main():
    """
   Orchestrates the verification process for all messages.
   <p>
   This function serves as the main entry point for the script's logic.
   It iterates through the global list of messages, calls the verification
   function for each one, and prints a human-readable result to the console
   indicating whether each message has been tampered with.
   """
    for i, msg_data in enumerate(MESSAGES_TO_VERIFY, 1):
        message_text = msg_data["text"]
        provided_hmac = msg_data["hmac"]

        is_valid = verify_hmac(message_text, provided_hmac, KEY_1, KEY_2)

        if is_valid:
            print(f"Message {i} (\"{message_text}\") is NOT tampered with.")
        else:
            print(f"Message {i} (\"{message_text}\") HAS BEEN tampered with.")

if __name__ == "__main__":
    # This block ensures that the main() function is called only when
    # the script is executed directly from the command line.
    main()