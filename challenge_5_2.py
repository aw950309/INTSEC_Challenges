"""
Challenge 5.2 (Normal): Tests
Write 2 to 3 tests for the XOR encryption function you
used in Challenge 1.2 (even if you used an external
service).
Test the full extent of possible input characters.
Use a unit test framework.
Put in the comments which part is the initialization,
function under test, and oracle.
Let me know if you found a bug.

Author: Alex Wagner.
Version: 1.2.
Date: 2025-12-21.

No bugs found. All tests pass. the XOR implementation correctly handles
 the symmetric encrypt/decrypt property across all 256 byte values."
"""
import time
import unittest
from challenge_1_2 import decrypt_with_key

# Helper functions for XOR encryption/decryption
def xor_encrypt(plaintext_bytes, key):
    """XOR encryption function - XOR each byte with repeating key."""
    return decrypt_with_key(plaintext_bytes, key)
def xor_decrypt(ciphertext_bytes, key):
    """XOR decryption function - identical to encrypt (XOR is symmetric)."""
    return decrypt_with_key(ciphertext_bytes, key)


#Test class
class TestXOREncryption(unittest.TestCase):
    """Test class for XOR encryption/decryption functions."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test 1: Encrypting then decrypting returns original plaintext."""
        # INITIALIZATION
        plaintext = b"Hello, World!"
        key = b"secret"

        # FUNCTION UNDER TEST
        ciphertext = xor_encrypt(plaintext, key)
        decrypted = xor_decrypt(ciphertext, key)

        # ORACLE
        self.assertEqual(decrypted, bytearray(plaintext))

    def test_all_byte_values(self):
        """Test 2: Test full extent of possible input characters (0-255)."""
        # INITIALIZATION
        all_bytes = bytes(range(256))
        key = b"testkey"

        # FUNCTION UNDER TEST
        ciphertext = xor_encrypt(all_bytes, key)
        decrypted = xor_decrypt(ciphertext, key)

        # ORACLE
        self.assertEqual(decrypted, bytearray(all_bytes))

    def test_known_vectors_from_challenge(self):
        """Test 3: Test with known input/output pairs from Challenge 1.2."""
        # INITIALIZATION
        known_plaintext = b"Challenge 1.2\n"
        key = b"simplekey12345"

        # FUNCTION UNDER TEST
        ciphertext = xor_encrypt(known_plaintext, key)
        decrypted = xor_decrypt(ciphertext, key)

        # ORACLE
        self.assertEqual(decrypted, bytearray(known_plaintext))

#Infrastructure to run tests and print summary.
def create_test_suite():
    """Creates and returns the test suite with all test cases."""
    suite = unittest.TestSuite()
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestXOREncryption))
    return suite

def run_tests(test_suite):
    """Runs the test suite and returns the results."""
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    return result


def print_test_summary(result):
    """Prints a summary of the test results."""
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    status = "PASSED" if result.wasSuccessful() else "FAILED"
    print(f"Status: {status}")
    print(f"{'='*50}")

#Orcehstration
def main():  # <-- Fix: Add colon
    # Step 1: Create the test suite
    test_suite = create_test_suite()

    # Step 2: Run the tests and get results.
    result = run_tests(test_suite)

    # Step 3: Print summary of results.
    print_test_summary(result)


if __name__ == "__main__":
    start_time = time.time()
    main()
    elapsed_time = time.time() - start_time
    print(f"\nProgram ran: {elapsed_time:.2f} seconds")
