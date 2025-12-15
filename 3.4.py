""""
Challenge 3.4 Solver
Goal 1: Find Bob's next OTP given f25a, cbc9.
Goal 2: Find Charlotte's potential next OTPs given 1ccf, 1*** and n < 100.

Use tiny_h_otp.py to compute TinyH-OTP values.

Author: Alex Wagner
Version: 4.
Date: 2025-12-15.
"""
from collections import Counter

import tiny_h_otp
from progress_tracker import ProgressTracker

# Constants
MAX_16BIT = 0x10000  # 65536
MAX_STEP = 100
CHARLOTTE_OTP2_RANGE = 0x1000  # 4096 possibilities for 1***


def find_master_password_from_previous_otps(otp1: str, otp2: str, tracker=None) -> str:
    """
    Finds the Master Password (mp) given the two previous OTPs
    that produces them using TinyH-OTP.
    Returns the found Master Password as a 4-hex-char string, or None if not found.
    """
    otp1_int = int(otp1, 16)
    otp2_int = int(otp2, 16)

    # Loop that iterates through every possible Master Password (guess_mp) from 0 to 65535.
    # It tries each guess to see if it produces the OTP
    for guess_mp_int in range(0, MAX_16BIT):

        # Helper: Need to convert the integer to a 4-character hex string.
        guess_mp_hex = f"{guess_mp_int:04x}"


        state = guess_mp_hex
        for n in range(100):
            state_int = (int(state, 16))
            if (state_int ^ guess_mp_int) == otp1_int:
                state_n1 = tiny_h_otp.TinyH(state)
                if (int(state_n1, 16) ^ guess_mp_int) == otp2_int:
                    print(f"Found Bob's Master Password: {guess_mp_hex}, at step n={n}")

                    return guess_mp_hex

            state = tiny_h_otp.TinyH(state)  # Reuse for next iteration

    if tracker:
        tracker.finish()
    return None


# Step 3: Use the the discovered MP to generate the given OTP/step u want.
def calculate_next_otp(master_password: str, step: int) -> str:
    """Calculates  next OTP/step 3"""
    otp3 = tiny_h_otp.TinyH_OTP(master_password, step)
    return otp3


def find_step_for_otp(master_password: str, otp: str, max_step: int) -> int | None:
    """Finds the step n where TinyH-OTP(mp, n) == otp.
    Returns n if found within max_step, otherwise None.
    """
    for n in range(0, max_step):  # Steps start at 1 (incremented before generation)
        if tiny_h_otp.TinyH_OTP(master_password, n) == otp:
            return n
    return None


def find_all_steps_for_otp(master_password: str, otp: str, max_step: int) -> list[int]:
    """Finds ALL steps where TinyH-OTP(mp, n) == otp."""
    steps = []
    for n in range(0, max_step):
        if tiny_h_otp.TinyH_OTP(master_password, n) == otp:
            steps.append(n)
    return steps


def find_charlotte_solutions(otp1: str, otp2_prefix: str, max_step: int, tracker=None) -> list:
    """Find all (mp, n, otp2, otp3) where OTP1 matches and OTP2 starts with prefix."""
    otp1_int = int(otp1, 16)
    solutions = []

    for mp_int in range(MAX_16BIT):
        mp_hex = f"{mp_int:04x}"
        state = mp_hex

        for n in range(max_step):
            state_int = int(state, 16)
            if (state_int ^ mp_int) == otp1_int:
                state_n1 = tiny_h_otp.TinyH(state)
                otp2_int = int(state_n1, 16) ^ mp_int
                otp2_hex = f"{otp2_int:04x}"

                if otp2_hex.startswith(otp2_prefix):
                    state_n2 = tiny_h_otp.TinyH(state_n1)
                    otp3_int = int(state_n2, 16) ^ mp_int
                    otp3_hex = f"{otp3_int:04x}"
                    solutions.append((mp_hex, n, otp2_hex, otp3_hex))

            state = tiny_h_otp.TinyH(state)

    return solutions


# Following the main logic of my pseudo-code.
def main():
    # Part A: Goal 1: Solve for Bob.
    # Part B: Goal 2: Solve for Charlotte.
    BOB_OTP1 = "f25a"
    BOB_OTP2 = "cbc9"
    otp1 = BOB_OTP1
    otp2 = BOB_OTP2

    # Step 2: Find the Master Password (MP) that produces the OTPs.
    print("Searching for Bob's master password...")
    master_password = find_master_password_from_previous_otps(otp1, otp2)

    # Step 3: Figure out the wanted OTP for Bob using the found Master Password.
    if master_password is None:
        print("Error: Could not find a master password for the given OTPs.")
    else:
        otp3 = calculate_next_otp(master_password, 3)

        # Step 4: Print the next OTP.
        bob_otp3 = otp3
        print(f"Bob's next OTP is: {bob_otp3}")

    # Part B: Goal 2: Solve for Charlotte.

    print("\nSearching for Charlotte's solutions...")
    # Tracker + spinner is just for fun and not neccessary.
    # charlotte_tracker = ProgressTracker(MAX_16BIT)
    charlotte_solutions = find_charlotte_solutions("1ccf", "1", MAX_STEP , tracker=None)

    # Analyse results
    print(f"\nFound {len(charlotte_solutions)} possible solutions for Charlotte.")

    # Count frequency of each OTP3.
    otp3_counts = Counter(sol[3] for sol in charlotte_solutions)

    # Collect unique OTP3 candidatesm
    unique_otp3s = set(sol[3] for sol in charlotte_solutions)

    print(f"\nCharlotte's OTP3 candidates ({len(unique_otp3s)} unique):")
    for otp3 in sorted(unique_otp3s):
        print(f"  {otp3}")

    print(f"\nEach has probability: 1/{len(unique_otp3s)} = {1 / len(unique_otp3s):.0%}")

    # Alice can try three times..
    max_attempts = 3
    success_probability = min(len(otp3_counts), max_attempts) / len(otp3_counts)
    print(f"\nWith {max_attempts} allowed attempts and {len(otp3_counts)} candidates:")
    print(f"Probability of success: {max_attempts}/{len(otp3_counts)} = {success_probability:.0%}")


if __name__ == "__main__":
    import time
    start_time = time.time()
    main()
    elapsed_time = time.time() - start_time
    print(f"\nProgram ran: {elapsed_time:.2f} seconds")
